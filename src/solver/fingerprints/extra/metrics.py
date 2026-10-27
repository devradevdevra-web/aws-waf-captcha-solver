import logging
import random
from typing import List, TypedDict

logger = logging.getLogger(__name__)



class MetricDict(TypedDict):
    name: str
    value: float
    unit: str


class MetricsGenerator:
    def __init__(self) -> None:
        self.metrics: List[MetricDict] = []

    def _create_metric(self, name: str, value: float, unit: str = "2") -> MetricDict:
        return {
            "name": name,
            "value": float(value),
            "unit": unit
        }

    def build_metrics(self) -> List[MetricDict]:

        rand = random.uniform

        self.metrics = [
            self._create_metric("2", rand(0, 1)),
            self._create_metric("1", rand(10, 20)),
            self._create_metric("5", rand(0, 1)),
            self._create_metric("6", rand(50, 60)),
            self._create_metric("0", rand(130, 140)),

            self._create_metric("3", 4),
            self._create_metric("4", 36.5),
            self._create_metric("100", 0),
            self._create_metric("101", 0),
            self._create_metric("102", 0),
            self._create_metric("103", 8),
            self._create_metric("104", 0),
            self._create_metric("105", 0),
            self._create_metric("106", 0),
            self._create_metric("107", 0),
            self._create_metric("108", 1),
            self._create_metric("110", 0),
            self._create_metric("111", 2),
            self._create_metric("112", 0),
            self._create_metric("114", 0),
            self._create_metric("115", 0),

            self._create_metric("7", 0, "4"),
            self._create_metric("8", 1, "4"),
        ]

        logger.debug("Generated %d metrics.", len(self.metrics))
        
        return self.metrics