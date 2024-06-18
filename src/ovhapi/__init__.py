import ovh
import logging

class OvhObject:
    def __init__(self, client: ovh.Client, logger: logging.Logger = None):
        self.client = client
        if logger is None:
            self.logger = logging.getLogger(__name__)
        else:
            self.logger = logger

    def _ovh_api_get(self, uri: str):
        try:
            data = self.client.get(uri)
            return data
        except Exception as e:
            self.logger.exception(f"GET {uri}", exc_info=True, stack_info=True)
            raise e

    def _ovh_api_delete(self, uri: str):
        try:
            data = self.client.delete(uri)
            return data
        except Exception as e:
            self.logger.exception(f"DELETE {uri}", exc_info=True, stack_info=True)
            raise e

    def _ovh_api_post(self, uri: str, data: dict):
        try:
            resp = self.client.post(uri, **data)
            return resp
        except Exception as e:
            self.logger.exception(f"POST {uri} {data}", exc_info=True, stack_info=True)
            raise e
