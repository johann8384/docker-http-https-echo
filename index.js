var express = require('express')
var http = require('http')
var https = require('https')
var app = express()
const os = require('os');
const jwt = require('jsonwebtoken');
var concat = require('concat-stream');

const { format, createLogger, transports } = require("winston");
const expressWinston = require('express-winston');
const LokiTransport = require("winston-loki");
const MESSAGE = Symbol.for('message');

const promClient = require('prom-client');
const collectDefaultMetrics = promClient.collectDefaultMetrics;
collectDefaultMetrics({ prefix: process.env.JAEGER_SERVER_NAME });

const PrometheusMetricsFactory = require('jaeger-client').PrometheusMetricsFactory;
const namespace = process.env.JAEGER_SERVER_NAME;
const metrics = new PrometheusMetricsFactory(promClient, namespace);

const histogram = new promClient.Histogram({
  name: 'echo_duration',
  help: 'Duration of HTTP requests in ms',
  labelNames: ['method', 'status_code'],
  buckets: [0.1, 5, 15, 50, 100, 500]
});

var traceID = '';

const jsonFormatter = (logEntry) => {
  const base = { timestamp: new Date(),  trace: traceID};
  const json = Object.assign(base, logEntry)
  logEntry[MESSAGE] = JSON.stringify(json);
  return logEntry;
}

const traceLogger = createLogger({
  transports: [
    new transports.Console(),
    new LokiTransport({
      host: "http://loki:3100"
    })
  ],
  format: format.combine(
    format.colorize(),
    format(jsonFormatter)()
  )
});

const commonLogger = createLogger({
  transports: [
    new transports.Console(),
    new LokiTransport({
      host: "http://loki:3100"
    })
  ],
  format: format.combine(
    format.colorize(),
    format(jsonFormatter)()
  )
});

const config = { sampler: { type: 'const', param: 1 }};
const options = { metrics: metrics,  logger: traceLogger };
const tracer = require('jaeger-client').initTracerFromEnv(config, options)
const opentracing = require('opentracing')
opentracing.initGlobalTracer(tracer)

app.set('json spaces', 2);
app.set('trust proxy', ['loopback', 'linklocal', 'uniquelocal']);

app.use(expressWinston.logger({
  transports: [
    new transports.Console(),
    new LokiTransport({
      host: "http://loki:3100"
    })
  ],
  format: format.combine(
    format.colorize(),
    format(jsonFormatter)()
  )
}));

app.use(function(req, res, next) {
  commonLogger.debug('handling trace')
  const end = histogram.startTimer();

  const tracer = opentracing.globalTracer();
  // Extracting the tracing headers from the incoming http request
  const wireCtx = tracer.extract(opentracing.FORMAT_HTTP_HEADERS, req.headers)
  // Creating our span with context from incoming request
  const span = tracer.startSpan(req.path, { childOf: wireCtx })
  // Use the log api to capture a log
  span.log({ event: 'request_received' })

  // Use the setTag api to capture standard span tags for http traces
  span.setTag(opentracing.Tags.HTTP_METHOD, req.method)
  span.setTag(opentracing.Tags.SPAN_KIND, opentracing.Tags.SPAN_KIND_RPC_SERVER)
  span.setTag(opentracing.Tags.HTTP_URL, req.path)

  // include trace ID in headers so that we can debug slow requests we see in
  // the browser by looking up the trace ID found in response headers
  const responseHeaders = {}
  tracer.inject(span, opentracing.FORMAT_HTTP_HEADERS, responseHeaders)
  res.set(responseHeaders)

  commonLogger.debug(JSON.stringify(tracer));

  // add the span to the request object for any other handler to use the span
  Object.assign(req, { span })

  // finalize the span when the response is completed
  const finishSpan = () => {
    if (res.statusCode >= 500) {
      // Force the span to be collected for http errors
      span.setTag(opentracing.Tags.SAMPLING_PRIORITY, 1)
      // If error then set the span to error
      span.setTag(opentracing.Tags.ERROR, true)

      // Response should have meaning info to futher troubleshooting
      span.log({ event: 'error', message: res.statusMessage })
    }
    // Capture the status code
    span.setTag(opentracing.Tags.HTTP_STATUS_CODE, res.statusCode)
    span.log({ event: 'request_end' })
    span.finish()
  }
  res.on('finish', finishSpan)
  end({ method: req.method, 'status_code': 200 });
  next()
});

// expose our metrics at the default URL for Prometheus
app.get('/metrics', (request, response) => {
  response.set('Content-Type', promClient.register.contentType);
  response.send(promClient.register.metrics());
});

app.use(function(req, res, next){
  req.pipe(concat(function(data){
    req.body = data.toString('utf8');
    next();
  }));
});

app.all('*', (req, res) => {
  const end = histogram.startTimer();
  const echo = {
    path: req.path,
    headers: req.headers,
    method: req.method,
    body: req.body,
    cookies: req.cookies,
    fresh: req.fresh,
    hostname: req.hostname,
    ip: req.ip,
    ips: req.ips,
    protocol: req.protocol,
    query: req.query,
    subdomains: req.subdomains,
    xhr: req.xhr,
    os: {
      hostname: os.hostname()
    },
    connection: {
      servername: req.connection.servername
    }
  };
  if (process.env.JWT_HEADER) {
    let token = req.headers[process.env.JWT_HEADER.toLowerCase()];
    if (!token) {
      echo.jwt = token;
    } else {
      token = token.split(" ").pop();
      const decoded = jwt.decode(token, {complete: true});
      echo.jwt = decoded;
    }
  }
  res.json(echo);
  if (process.env.LOG_IGNORE_PATH != req.path) {
    commonLogger.debug('-----------------')
    commonLogger.debug(echo);
  }
  end({ method: req.method, 'status_code': 200 });
});

 // express-winston errorLogger makes sense AFTER the router.
app.use(expressWinston.errorLogger({
  transports: [
    new transports.Console(),
    new LokiTransport({
      host: "http://loki:3100"
    })
  ],
  format: format.combine(
    format.colorize(),
    format(jsonFormatter)()
  )
}));
 
// Optionally you can include your custom error handler after the logging.
app.use(expressWinston.errorLogger({
  transports: [
    new transports.Console(),
    new LokiTransport({
      host: "http://loki:3100"
    })
  ],
  format: format.combine(
    format.colorize(),
    format(jsonFormatter)()
  ),
  dumpExceptions: true,
  showStack: true
}));

const sslOpts = {
  key: require('fs').readFileSync('privkey.pem'),
  cert: require('fs').readFileSync('fullchain.pem'),
};

var httpServer = http.createServer(app).listen(process.env.HTTP_PORT || 80);
var httpsServer = https.createServer(sslOpts,app).listen(process.env.HTTPS_PORT || 443);

let calledClose = false;

process.on('exit', function () {
  if (calledClose) return;
  commonLogger.debug('Got exit event. Trying to stop Express server.');
  server.close(function() {
    commonLogger.debug("Express server closed");
  });
});

process.on('SIGINT', shutDown);
process.on('SIGTERM', shutDown);

function shutDown(){
  commonLogger.debug('Got a kill signal. Trying to exit gracefully.');
  calledClose = true;
  httpServer.close(function() {
    httpsServer.close(function() {
      commonLogger.debug("HTTP and HTTPS servers closed. Asking process to exit.");
      process.exit()
    });
    
  });
}
