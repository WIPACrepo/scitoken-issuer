# type: ignore
import asyncio
import logging

from rest_tools.utils import from_environment

from .server import create_server

# handle logging
setlevel = {
    'CRITICAL': logging.CRITICAL,  # execution cannot continue
    'FATAL': logging.CRITICAL,
    'ERROR': logging.ERROR,  # something is wrong, but try to continue
    'WARNING': logging.WARNING,  # non-ideal behavior, important event
    'WARN': logging.WARNING,
    'INFO': logging.INFO,  # initial debug information
    'DEBUG': logging.DEBUG  # the things no one wants to see
}

default_config = {
    'LOG_LEVEL': 'INFO',
}
config = from_environment(default_config)
if config['LOG_LEVEL'].upper() not in setlevel:
    raise Exception('LOG_LEVEL is not a proper log level')
logformat = '%(asctime)s %(levelname)s %(name)s %(module)s:%(lineno)s - %(message)s'

logging.basicConfig(format=logformat, level=setlevel[config['LOG_LEVEL'].upper()])

# start server
create_server()
asyncio.get_event_loop().run_forever()
