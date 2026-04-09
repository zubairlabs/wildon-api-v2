import http from "k6/http";
import { check, sleep } from "k6";

export const options = {
  vus: 20,
  duration: "2m",
  thresholds: {
    http_req_failed: ["rate<0.01"],
    http_req_duration: ["p(95)<300"],
  },
};

const baseUrl = __ENV.BASE_URL || "http://127.0.0.1:8080";

export default function () {
  const res = http.get(`${baseUrl}/health`);
  check(res, {
    "status is 200": (r) => r.status === 200,
    "latency under 300ms": (r) => r.timings.duration < 300,
  });
  sleep(0.25);
}
