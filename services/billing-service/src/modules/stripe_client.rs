//! Lightweight Stripe API client using reqwest + form-encoded bodies.
//! We avoid the full `stripe-rust` crate in favour of direct REST calls.

use serde::Deserialize;
use std::env;

#[derive(Clone)]
pub struct StripeClient {
    secret_key: String,
    http: reqwest::Client,
}

#[derive(Debug, Deserialize)]
pub struct StripeCustomer {
    pub id: String,
}

#[derive(Debug, Deserialize)]
pub struct StripeSetupIntent {
    pub id: String,
    pub client_secret: String,
}

#[derive(Debug, Deserialize)]
pub struct StripePaymentMethod {
    pub id: String,
    pub card: Option<StripeCard>,
}

#[derive(Debug, Deserialize)]
pub struct StripeCard {
    pub brand: String,
    pub last4: String,
    pub exp_month: i32,
    pub exp_year: i32,
}

#[derive(Debug, Deserialize)]
pub struct StripeSubscription {
    pub id: String,
    pub status: String,
    pub current_period_start: i64,
    pub current_period_end: i64,
    pub latest_invoice: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct StripeRefund {
    pub id: String,
    pub status: String,
    pub amount: i64,
}

#[derive(Debug)]
pub struct StripeError {
    pub message: String,
}

impl std::fmt::Display for StripeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "stripe: {}", self.message)
    }
}

impl StripeClient {
    /// Load Stripe credentials from environment.
    ///
    /// Checks `STRIPE_MODE` (default: "test") to pick the right keys:
    ///   - test → `STRIPE_TEST_SECRET_KEY`
    ///   - live → `STRIPE_LIVE_SECRET_KEY`
    ///
    /// Falls back to `STRIPE_SECRET_KEY` if the mode-specific var isn't set.
    pub fn from_env() -> Option<Self> {
        let mode = env::var("STRIPE_MODE")
            .unwrap_or_else(|_| "test".to_string())
            .to_ascii_lowercase();

        let key = match mode.as_str() {
            "live" | "production" => env::var("STRIPE_LIVE_SECRET_KEY")
                .or_else(|_| env::var("STRIPE_SECRET_KEY"))
                .ok()?,
            _ => {
                // test mode (default)
                env::var("STRIPE_TEST_SECRET_KEY")
                    .or_else(|_| env::var("STRIPE_SECRET_KEY"))
                    .ok()?
            }
        };

        if key.is_empty() {
            return None;
        }

        tracing::info!(mode = %mode, key_prefix = &key[..7], "stripe client initialized");

        Some(Self {
            secret_key: key,
            http: reqwest::Client::new(),
        })
    }

    /// Which mode is active (for logging/display).
    pub fn mode() -> String {
        env::var("STRIPE_MODE")
            .unwrap_or_else(|_| "test".to_string())
            .to_ascii_lowercase()
    }

    async fn post_form(
        &self,
        path: &str,
        params: &[(&str, &str)],
    ) -> Result<serde_json::Value, StripeError> {
        let url = format!("https://api.stripe.com/v1{path}");
        let resp = self
            .http
            .post(&url)
            .basic_auth(&self.secret_key, None::<&str>)
            .form(params)
            .send()
            .await
            .map_err(|e| StripeError {
                message: e.to_string(),
            })?;

        let status = resp.status();
        let body: serde_json::Value = resp.json().await.map_err(|e| StripeError {
            message: e.to_string(),
        })?;

        if !status.is_success() {
            let msg = body["error"]["message"]
                .as_str()
                .unwrap_or("unknown stripe error");
            return Err(StripeError {
                message: msg.to_string(),
            });
        }
        Ok(body)
    }

    async fn get(&self, path: &str) -> Result<serde_json::Value, StripeError> {
        let url = format!("https://api.stripe.com/v1{path}");
        let resp = self
            .http
            .get(&url)
            .basic_auth(&self.secret_key, None::<&str>)
            .send()
            .await
            .map_err(|e| StripeError {
                message: e.to_string(),
            })?;

        let status = resp.status();
        let body: serde_json::Value = resp.json().await.map_err(|e| StripeError {
            message: e.to_string(),
        })?;

        if !status.is_success() {
            let msg = body["error"]["message"]
                .as_str()
                .unwrap_or("unknown stripe error");
            return Err(StripeError {
                message: msg.to_string(),
            });
        }
        Ok(body)
    }

    async fn delete(&self, path: &str) -> Result<serde_json::Value, StripeError> {
        let url = format!("https://api.stripe.com/v1{path}");
        let resp = self
            .http
            .delete(&url)
            .basic_auth(&self.secret_key, None::<&str>)
            .send()
            .await
            .map_err(|e| StripeError {
                message: e.to_string(),
            })?;

        let status = resp.status();
        let body: serde_json::Value = resp.json().await.map_err(|e| StripeError {
            message: e.to_string(),
        })?;

        if !status.is_success() {
            let msg = body["error"]["message"]
                .as_str()
                .unwrap_or("unknown stripe error");
            return Err(StripeError {
                message: msg.to_string(),
            });
        }
        Ok(body)
    }

    /// Create or retrieve a Stripe customer for a given user.
    pub async fn get_or_create_customer(
        &self,
        user_id: &str,
        email: &str,
    ) -> Result<StripeCustomer, StripeError> {
        let body = self
            .post_form(
                "/customers",
                &[("email", email), ("metadata[user_id]", user_id)],
            )
            .await?;
        Ok(StripeCustomer {
            id: body["id"].as_str().unwrap_or_default().to_string(),
        })
    }

    /// Create a SetupIntent for collecting a payment method.
    pub async fn create_setup_intent(
        &self,
        customer_id: &str,
    ) -> Result<StripeSetupIntent, StripeError> {
        let body = self
            .post_form(
                "/setup_intents",
                &[
                    ("customer", customer_id),
                    ("payment_method_types[]", "card"),
                ],
            )
            .await?;
        Ok(StripeSetupIntent {
            id: body["id"].as_str().unwrap_or_default().to_string(),
            client_secret: body["client_secret"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
        })
    }

    /// Retrieve a payment method by ID.
    pub async fn get_payment_method(
        &self,
        pm_id: &str,
    ) -> Result<StripePaymentMethod, StripeError> {
        let body = self.get(&format!("/payment_methods/{pm_id}")).await?;
        Ok(StripePaymentMethod {
            id: body["id"].as_str().unwrap_or_default().to_string(),
            card: body.get("card").map(|c| StripeCard {
                brand: c["brand"].as_str().unwrap_or_default().to_string(),
                last4: c["last4"].as_str().unwrap_or_default().to_string(),
                exp_month: c["exp_month"].as_i64().unwrap_or(0) as i32,
                exp_year: c["exp_year"].as_i64().unwrap_or(0) as i32,
            }),
        })
    }

    /// Attach a payment method to a customer.
    pub async fn attach_payment_method(
        &self,
        pm_id: &str,
        customer_id: &str,
    ) -> Result<(), StripeError> {
        self.post_form(
            &format!("/payment_methods/{pm_id}/attach"),
            &[("customer", customer_id)],
        )
        .await?;
        Ok(())
    }

    /// Detach a payment method from its customer.
    pub async fn detach_payment_method(&self, pm_id: &str) -> Result<(), StripeError> {
        self.post_form(&format!("/payment_methods/{pm_id}/detach"), &[])
            .await?;
        Ok(())
    }

    /// Create a subscription for a customer.
    pub async fn create_subscription(
        &self,
        customer_id: &str,
        price_id: &str,
        payment_method_id: &str,
        trial_days: i32,
    ) -> Result<StripeSubscription, StripeError> {
        let trial_str = trial_days.to_string();
        let mut params: Vec<(&str, &str)> = vec![
            ("customer", customer_id),
            ("items[0][price]", price_id),
            ("default_payment_method", payment_method_id),
            ("payment_behavior", "default_incomplete"),
            ("expand[]", "latest_invoice.payment_intent"),
        ];
        if trial_days > 0 {
            params.push(("trial_period_days", &trial_str));
        }
        let body = self.post_form("/subscriptions", &params).await?;
        Ok(StripeSubscription {
            id: body["id"].as_str().unwrap_or_default().to_string(),
            status: body["status"].as_str().unwrap_or_default().to_string(),
            current_period_start: body["current_period_start"].as_i64().unwrap_or(0),
            current_period_end: body["current_period_end"].as_i64().unwrap_or(0),
            latest_invoice: body["latest_invoice"]["id"].as_str().map(|s| s.to_string()),
        })
    }

    /// Cancel a subscription.
    pub async fn cancel_subscription(
        &self,
        sub_id: &str,
        at_period_end: bool,
    ) -> Result<StripeSubscription, StripeError> {
        if at_period_end {
            let body = self
                .post_form(
                    &format!("/subscriptions/{sub_id}"),
                    &[("cancel_at_period_end", "true")],
                )
                .await?;
            Ok(StripeSubscription {
                id: body["id"].as_str().unwrap_or_default().to_string(),
                status: body["status"].as_str().unwrap_or_default().to_string(),
                current_period_start: body["current_period_start"].as_i64().unwrap_or(0),
                current_period_end: body["current_period_end"].as_i64().unwrap_or(0),
                latest_invoice: None,
            })
        } else {
            let body = self.delete(&format!("/subscriptions/{sub_id}")).await?;
            Ok(StripeSubscription {
                id: body["id"].as_str().unwrap_or_default().to_string(),
                status: body["status"].as_str().unwrap_or("canceled").to_string(),
                current_period_start: body["current_period_start"].as_i64().unwrap_or(0),
                current_period_end: body["current_period_end"].as_i64().unwrap_or(0),
                latest_invoice: None,
            })
        }
    }

    /// Resume a subscription (unset cancel_at_period_end).
    pub async fn resume_subscription(
        &self,
        sub_id: &str,
    ) -> Result<StripeSubscription, StripeError> {
        let body = self
            .post_form(
                &format!("/subscriptions/{sub_id}"),
                &[("cancel_at_period_end", "false")],
            )
            .await?;
        Ok(StripeSubscription {
            id: body["id"].as_str().unwrap_or_default().to_string(),
            status: body["status"].as_str().unwrap_or_default().to_string(),
            current_period_start: body["current_period_start"].as_i64().unwrap_or(0),
            current_period_end: body["current_period_end"].as_i64().unwrap_or(0),
            latest_invoice: None,
        })
    }

    /// Retrieve the latest state of a subscription from Stripe (for webhook ordering safety).
    pub async fn get_subscription(&self, sub_id: &str) -> Result<StripeSubscription, StripeError> {
        let body = self.get(&format!("/subscriptions/{sub_id}")).await?;
        Ok(StripeSubscription {
            id: body["id"].as_str().unwrap_or_default().to_string(),
            status: body["status"].as_str().unwrap_or_default().to_string(),
            current_period_start: body["current_period_start"].as_i64().unwrap_or(0),
            current_period_end: body["current_period_end"].as_i64().unwrap_or(0),
            latest_invoice: body["latest_invoice"].as_str().map(|s| s.to_string()),
        })
    }

    /// Attempt to pay an open invoice.
    pub async fn pay_invoice(&self, invoice_id: &str) -> Result<String, StripeError> {
        let body = self
            .post_form(&format!("/invoices/{invoice_id}/pay"), &[])
            .await?;
        Ok(body["status"].as_str().unwrap_or("unknown").to_string())
    }

    /// Create a refund against a payment intent.
    pub async fn create_refund(
        &self,
        payment_intent_id: &str,
        amount_cents: i32,
    ) -> Result<StripeRefund, StripeError> {
        let amount_str = amount_cents.to_string();
        let body = self
            .post_form(
                "/refunds",
                &[
                    ("payment_intent", payment_intent_id),
                    ("amount", &amount_str),
                ],
            )
            .await?;
        Ok(StripeRefund {
            id: body["id"].as_str().unwrap_or_default().to_string(),
            status: body["status"].as_str().unwrap_or_default().to_string(),
            amount: body["amount"].as_i64().unwrap_or(0),
        })
    }
}
