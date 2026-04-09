import http from "k6/http";
import { check, sleep } from "k6";

export const options = {
  stages: [
    { duration: "5m", target: 200 },
    { duration: "20m", target: 500 },
    { duration: "20m", target: 500 },
    { duration: "5m", target: 0 },
  ],
  thresholds: {
    http_req_failed: ["rate<0.02"],
    http_req_duration: ["p(95)<400", "p(99)<800"],
  },
};

const baseUrl = __ENV.BASE_URL || "http://127.0.0.1:8080";
const loginSub = __ENV.LOGIN_SUB || "soak-user";

function loginToken() {
  const body = JSON.stringify({ sub: loginSub });
  const headers = { "Content-Type": "application/json" };
  const res = http.post(`${baseUrl}/v1/auth/login`, body, { headers });
  check(res, { "login status is 200": (r) => r.status === 200 });
  const payload = res.json();
  return payload.access_token;
}

export default function () {
  const token = loginToken();
  const headers = {
    Authorization: `Bearer ${token}`,
    "x-device-id": `device-${__VU}`,
    "x-app-id": __ENV.APP_ID || "guardianone",
  };

  const me = http.get(`${baseUrl}/v1/users/me`, { headers });
  check(me, {
    "me status < 500": (r) => r.status < 500,
    "me p95 budget": (r) => r.timings.duration < 500,
  });

  sleep(0.3);
}
