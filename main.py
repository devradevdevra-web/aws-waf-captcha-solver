import re
import json
import logging, random
from typing import Tuple, Dict, Any, Union, List, Optional, Mapping
from types import TracebackType
from src.solver.fingerprints.fingerprints import FingerprintGenerator
from curl_cffi import requests, CurlMime
from src.solver.pow.solver import ChallengeSolverRouter
from src.solver.fingerprints.extra.metrics import MetricsGenerator
from src.solver.logger.logger import logger




class BinanceClient:
    def __init__(self) -> None:
        self.base_url: str = "https://www.binance.com/en-GB"
        self.user_agent: str = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/156.0.0.0 Safari/537.36"
        )
        
        self.session = requests.Session(impersonate="chrome", default_headers=False)
        self._setup_headers()

        self.metrics: list = []
        self.encrypted: str | None = None
        self.checksum: str | None = None
        
        self.goku_props: dict[str, Any] = {}
        self.goku_key: str | None = None
        self.goku_iv: str | None = None
        self.goku_context: str | None = None

    def _setup_headers(self) -> None:
        self.session.headers.update({
            "user-agent": self.user_agent,
            "accept": "*/*",
            "accept-language": "en-US,en;q=0.6",
            "accept-encoding": "gzip, deflate, br, zstd",
            "origin": "https://www.binance.com",
            "referer": "https://www.binance.com/",
            "cache-control": "no-cache",
            "pragma": "no-cache",
            "priority": "u=1, i",
            "sec-ch-ua": '"Not:A-Brand";v="8", "Chromium";v="156", "Brave";v="156"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "cross-site",
            "sec-gpc": "1",
        })

    def generate_fingerprint(self) -> Tuple[str, str]:

        generator = FingerprintGenerator(user_agent=self.user_agent, referrer=self.base_url, target_url=self.base_url)
        fingerprint = generator.generate_fingerprint()

        self.encrypted, self.checksum = generator.encrypt_fingerprint(fingerprint)
        
        return self.encrypted, self.checksum

    def extract(self, html: str):
        goku_props = json.loads(
            html.split("window.gokuProps = ")[1].split(";")[0]
        )
        host = html.split('src="https://')[1].split("/challenge.js")[0]
        self.host = host
        
        self.inputs_url: str = f"https://{host}/inputs?client=browser"
        
        return goku_props, host

    def is_challenged(self, headers: Mapping[str, str]) -> bool:
        return headers.get("x-amzn-waf-action") == "challenge"

    def get_goku_props(self) -> dict[str, Any]:
        logger.debug(f"Fetching gokuProps from {self.base_url}")

        try:
            response = self.session.get(
                self.base_url,
                headers={"accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
                timeout=30,
            )
            response.raise_for_status()

        except requests.RequestException as e:
            logger.error(f"Failed to fetch base URL: {e}")
            raise

        if self.is_challenged(response.headers):
            logger.warn("Request intercepted by AWS WAF challenge.")

        self.extract(response.text)

        match = re.search(r"window\.gokuProps\s*=\s*(\{.*?\})\s*;", response.text, flags=re.DOTALL)
        if not match:
            logger.error("window.gokuProps not found in HTML response.")
            raise ValueError("window.gokuProps not found in response")

        try:
            self.goku_props = json.loads(match.group(1))
            self.goku_key = self.goku_props.get("key")
            self.goku_iv = self.goku_props.get("iv")
            self.goku_context = self.goku_props.get("context")

            logger.success(f"Successfully loaded gokuProps: {str(self.goku_props)[:30]}...")
            return self.goku_props

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse gokuProps JSON: {e}")
            raise ValueError(f"Malformed JSON in gokuProps: {e}") from e

    def get_inputs(self) -> Tuple[Union[Dict[str, Any], str], Optional[str]]:
        logger.info(f"Fetching AWS inputs from {self.inputs_url[:40]}")

        try:
            response = self.session.get(self.inputs_url, timeout=30)
            response.raise_for_status()
            data = response.json()
            solution = None

            if isinstance(data, dict) and "challenge_type" in data:
                try:
                    logger.info("Proof-of-Work Detected Solving")
                    
                    router = ChallengeSolverRouter()
                    solution = router.solve_payload(data)
                    
                    logger.info(f"Proof-of-Work Successfully Solved: {solution}")
                except Exception as e:
                    logger.error("Failed to solve challenge: %s", e)
                    raise

            return data, solution

        except requests.exceptions.RequestException as e:
            logger.error("Network error fetching inputs: %s", e)
            raise
        except ValueError:
            logger.warn("Response was not valid JSON, returning raw text.")
            return response.text, None


    def validate_payload(self, payload: Dict[str, Any]) -> None:
        challenge = payload.get("challenge")

        if not isinstance(challenge, dict):
            raise ValueError("Payload 'challenge' must be a dictionary/object.")

        if "challenge" in challenge:
            raise ValueError(
                "Nested challenge detected. "
                "Check whether you passed the full inputs response by mistake."
            )
        
        if not challenge.get("input"):
            raise ValueError("Missing 'challenge.input'.")

        if not challenge.get("region"):
            raise ValueError("Missing 'challenge.region'.")



    def extract_challenge(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        challenge = inputs.get("challenge")
        
        if not challenge:
            raise ValueError("The provided inputs do not contain a 'challenge' key.")
        
        if "challenge" in challenge:
            challenge = challenge["challenge"]

 
        return challenge


    def build_payload(
        self, 
        challenge: Dict[str, Any], 
        metrics: List[Dict[str, Any]], 
        signal_name: str
    ) -> Dict[str, Any]:
      
        if not self.encrypted or not self.checksum:
            logger.error("Fingerprint not generated before building payload.")
            raise ValueError("Generate fingerprint first by calling generate_fingerprint().")

        if not self.goku_props:
            logger.error("gokuProps are missing.")
            raise ValueError("Get gokuProps first by calling get_goku_props().")

        if not isinstance(challenge, dict):
            raise TypeError(
                f"Expected 'challenge' to be a dictionary, got {type(challenge).__name__}"
            )

        if not isinstance(metrics, list):
            raise TypeError(
                f"Expected 'metrics' to be a list, got {type(metrics).__name__}"
            )

        try:
            extracted_challenge = self.extract_challenge(challenge)
        except ValueError as e:
            logger.error(f"Failed to extract challenge during payload build: {e}")
            raise

        payload = {
            "challenge": extracted_challenge,
            "signals": [
                {
                    "name": signal_name,
                    "value": {
                        "Present": self.encrypted
                    }
                }
            ],
            "checksum": self.checksum,
            "existing_token": "",
            "client": "Browser",
            "domain": "binance.com",
            "metrics": metrics,
            "goku_props": self.goku_props,
            "solution": ""
        }
        return payload

    def send_payload(self, payload: dict, solution: bytes | str) -> dict:
        mime = CurlMime()

        metadata_json = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        mime.addpart(name="solution_metadata", data=metadata_json)
        mime.addpart(name="solution_data", data=solution)

        headers = {
            k: v for k, v in self.session.headers.items()
            if k.lower() not in {"content-type", "content-length"}
        }

        url = f"{self.host}/mp_verify"

        try:
            response = self.session.post(
                url,
                headers=headers,
                multipart=mime,
                timeout=30
            )

            try:
                response_data = response.json()
            except ValueError:
                response_data = {"raw_response": response.text}

            return {
                "status_code": response.status_code,
                "data": response_data
            }
        finally:
            mime.close()

    def get_binance(self, token):
        url = "https://www.binance.com/en-GB"


        response = self.session.get(
            url,
            headers={
                "accept": "text/html,application/xhtml+xml,"
                        "application/xml;q=0.9,*/*;q=0.8",
                "referer": "https://www.binance.com/",
                "user-agent": self.user_agent,
            },
            timeout=30
        )
        if response.status_code == 200:
            logger.success(f"Successfully Solved AWS Captcha: {token}")
        if response.status_code == 202:
            logger.warn("Failed to Solve AWS")
        if response.status_code == 400:
            logger.error(f"unexpected status: {response.status_code}")

        return response


    def set_waf_cookie(self, result: dict):
        token = result.get("data", {}).get("token")

        if not token:
            raise ValueError("No AWS WAF token returned")

        self.session.cookies.set(
            name="aws-waf-token",
            value=token,
            domain=".binance.com",
            path="/",
            secure=True
        )

        return token

    def run(self) -> None:
        self.generate_fingerprint()

        self.get_goku_props() 
        inputs, solution = self.get_inputs()
        
        sensor_metrics = MetricsGenerator().build_metrics()
        
        payload = self.build_payload(inputs, sensor_metrics, "Zoey")
        self.validate_payload(payload)

        challenge_data = payload.get("challenge")
        if isinstance(challenge_data, dict) and "challenge" in challenge_data:
            payload["challenge"] = challenge_data["challenge"]
            self.validate_payload(payload)

        result = self.send_payload(payload, solution)
      
        if result.get("status_code") == 200:
            token = self.set_waf_cookie(result)
            response = self.get_binance(token)
        else:
            logger.warn(f"Payload failed with status: {result.get('status_code')}")

    def close(self) -> None:
        self.session.close()

    def __enter__(self):
        return self
        
    def __exit__(
        self, 
        exc_type: type[BaseException] | None, 
        exc_val: BaseException | None, 
        exc_tb: TracebackType | None
    ) -> None:
        self.close()



if __name__ == "__main__":
    with BinanceClient() as client:
        client.run()