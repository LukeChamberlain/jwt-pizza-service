const config = require('./config');

class Logger {
  httpLogger = (req, res, next) => {
    let send = res.send;
    res.send = (resBody) => {
      const logData = {
        authorized: !!req.headers.authorization,
        path: req.originalUrl,
        method: req.method,
        statusCode: res.statusCode,
        reqBody: JSON.stringify(req.body),
        resBody: JSON.stringify(resBody),
      };
      const level = this.statusToLogLevel(res.statusCode);
      this.log(level, 'http', logData);
      res.send = send;
      return res.send(resBody);
    };
    next();
  };

  logQuery(sql, params) {
    const logData = {
      query: sql,
      params: params,
    };
    this.log('info', 'db', logData);
  }

  logFactory(reqBody, resBody, statusCode) {
    const level = this.statusToLogLevel(statusCode);
    const logData = {
      statusCode,
      reqBody: JSON.stringify(reqBody),
      resBody: JSON.stringify(resBody),
    };
    this.log(level, 'factory', logData);
  }

  errorLogger = (err, req, res, next) => {
    const logData = {
      message: err.message,
      stack: err.stack,
      path: req?.originalUrl,
      method: req?.method,
    };
    this.log('error', 'exception', logData);
    next(err);
  };


  log(level, type, logData) {
    const labels = {
      component: config.logging.source,
      level: level,
      type: type,
    };
    const values = [this.nowString(), this.sanitize(logData)];
    const logEvent = { streams: [{ stream: labels, values: [values] }] };

    this.sendLogToGrafana(logEvent);
  }

  statusToLogLevel(statusCode) {
    if (statusCode >= 500) return 'error';
    if (statusCode >= 400) return 'warn';
    return 'info';
  }

  nowString() {
    return (Math.floor(Date.now()) * 1000000).toString();
  }

  sanitize(logData) {
    let str = JSON.stringify(logData);
    str = str.replace(/\\"password\\":\s*\\"[^"]*\\"/g, '\\"password\\": \\"*****\\"');
    str = str.replace(/\\"authorization\\":\s*\\"[^"]*\\"/gi, '\\"authorization\\": \\"*****\\"');
    str = str.replace(/\\"apiKey\\":\s*\\"[^"]*\\"/g, '\\"apiKey\\": \\"*****\\"');
    str = str.replace(/\\"token\\":\s*\\"[^"]*\\"/g, '\\"token\\": \\"*****\\"');
    return str;
  }

  sendLogToGrafana(event) {
    const body = JSON.stringify(event);
    fetch(config.logging.endpointUrl, {
      method: 'post',
      body: body,
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${config.logging.accountId}:${config.logging.apiKey}`,
      },
    }).then((res) => {
      if (!res.ok) console.log('Failed to send log to Grafana');
    });
  }
}

module.exports = new Logger();