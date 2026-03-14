const os = require("os");
const config = require("./config");

// ========================
// Metric Counters & State
// ========================

const requests = {};

const authMetrics = {
  successfulLogins: 0,
  failedLogins: 0,
};

const userMetrics = {
  activeUsers: 0,
};

const purchaseMetrics = {
  pizzasSold: 0,
  creationFailures: 0,
  revenue: 0,
  totalPizzaLatency: 0,
  pizzaPurchaseCount: 0,
};

// latencyMetrics must be at the top level so requestTracker can access it
const latencyMetrics = {
  totalServiceLatency: 0,
  serviceRequestCount: 0,
};

// ========================
// Public API
// ========================

function requestTracker(req, res, next) {
  const start = Date.now();
  const endpoint = `[${req.method}] ${req.path}`;
  requests[endpoint] = (requests[endpoint] || 0) + 1;

  res.on("finish", () => {
    latencyMetrics.totalServiceLatency += Date.now() - start;
    latencyMetrics.serviceRequestCount++;
  });

  next();
}

function authSuccess() {
  authMetrics.successfulLogins++;
  userMetrics.activeUsers++;
}

function authFailure() {
  authMetrics.failedLogins++;
}

function userLogout() {
  if (userMetrics.activeUsers > 0) {
    userMetrics.activeUsers--;
  }
}

function pizzaPurchase(success, latencyMs, price) {
  if (success) {
    purchaseMetrics.pizzasSold++;
    purchaseMetrics.revenue += price;
  } else {
    purchaseMetrics.creationFailures++;
  }
  purchaseMetrics.totalPizzaLatency += latencyMs;
  purchaseMetrics.pizzaPurchaseCount++;
}

// ========================
// System Metrics
// ========================

function getCpuUsagePercentage() {
  const cpuUsage = os.loadavg()[0] / os.cpus().length;
  return cpuUsage.toFixed(2) * 100;
}

function getMemoryUsagePercentage() {
  const totalMemory = os.totalmem();
  const freeMemory = os.freemem();
  const usedMemory = totalMemory - freeMemory;
  const memoryUsage = (usedMemory / totalMemory) * 100;
  return memoryUsage.toFixed(2);
}

function getAvgPizzaLatency() {
  if (purchaseMetrics.pizzaPurchaseCount === 0) return 0;
  return parseFloat(
    (purchaseMetrics.totalPizzaLatency / purchaseMetrics.pizzaPurchaseCount).toFixed(2)
  );
}

function getAvgServiceLatency() {
  if (latencyMetrics.serviceRequestCount === 0) return 0;
  return parseFloat(
    (latencyMetrics.totalServiceLatency / latencyMetrics.serviceRequestCount).toFixed(2)
  );
}

// ========================
// OTel Metric Builder
// ========================

function createMetric(metricName, metricValue, metricUnit, metricType, valueType, attributes) {
  attributes = { ...attributes, source: config.metrics.source };

  const metric = {
    name: metricName,
    unit: metricUnit,
    [metricType]: {
      dataPoints: [
        {
          [valueType]: metricValue,
          timeUnixNano: Date.now() * 1000000,
          attributes: [],
        },
      ],
    },
  };

  Object.keys(attributes).forEach((key) => {
    metric[metricType].dataPoints[0].attributes.push({
      key: key,
      value: { stringValue: String(attributes[key]) },
    });
  });

  if (metricType === "sum") {
    metric[metricType].aggregationTemporality = "AGGREGATION_TEMPORALITY_CUMULATIVE";
    metric[metricType].isMonotonic = true;
  }

  return metric;
}

function sendMetricToGrafana(metrics) {
  const body = {
    resourceMetrics: [
      {
        scopeMetrics: [
          {
            metrics,
          },
        ],
      },
    ],
  };

  fetch(config.metrics.endpointUrl, {
    method: "POST",
    body: JSON.stringify(body),
    headers: {
      Authorization: `Bearer ${config.metrics.accountId}:${config.metrics.apiKey}`,
      "Content-Type": "application/json",
    },
  })
    .then((response) => {
      if (!response.ok) {
        response.text().then((text) => {
          console.error(`Failed to send metrics: ${response.status} - ${text}`);
        });
      }
    })
    .catch((error) => {
      console.error("Error pushing metrics to Grafana:", error.message);
    });
}

// ========================
// Periodic Reporting
// ========================

function sendMetricsPeriodically(period = 10000) {
  setInterval(() => {
    try {
      const metrics = [];

      // HTTP request counts per endpoint
      Object.keys(requests).forEach((endpoint) => {
        metrics.push(
          createMetric("request", requests[endpoint], "1", "sum", "asInt", { endpoint })
        );
      });

      // Auth metrics
      metrics.push(createMetric("auth", authMetrics.successfulLogins, "1", "sum", "asInt", { result: "success" }));
      metrics.push(createMetric("auth", authMetrics.failedLogins, "1", "sum", "asInt", { result: "failure" }));

      // Active users
      metrics.push(createMetric("users", userMetrics.activeUsers, "1", "gauge", "asInt", {}));

      // System metrics
      metrics.push(createMetric("cpu", getCpuUsagePercentage(), "%", "gauge", "asDouble", {}));
      metrics.push(createMetric("memory", getMemoryUsagePercentage(), "%", "gauge", "asDouble", {}));

      // Pizza metrics
      metrics.push(createMetric("pizza", purchaseMetrics.pizzasSold, "1", "sum", "asInt", { type: "sold" }));
      metrics.push(createMetric("pizza", purchaseMetrics.creationFailures, "1", "sum", "asInt", { type: "failure" }));
      metrics.push(createMetric("revenue", purchaseMetrics.revenue, "USD", "sum", "asDouble", {}));

      // Latency metrics
      metrics.push(createMetric("latency", getAvgPizzaLatency(), "ms", "gauge", "asDouble", { type: "pizza" }));
      metrics.push(createMetric("latency", getAvgServiceLatency(), "ms", "gauge", "asDouble", { type: "service" }));

      sendMetricToGrafana(metrics);
    } catch (error) {
      console.error("Error sending metrics:", error);
    }
  }, period);

  console.log(`Metrics reporting started — pushing every ${period / 1000}s`);
}

// ========================
// Exports
// ========================

module.exports = {
  requestTracker,
  authSuccess,
  authFailure,
  userLogout,
  pizzaPurchase,
  sendMetricsPeriodically,
};