import argparse
import logging
from typing import Tuple
from deepdiff import DeepDiff
import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry
from urllib.parse import quote
import pprint
from concurrent.futures import ThreadPoolExecutor
import os
import random
import math
import json
import shutil
import time
import uuid


def diff_response(args: Tuple[str, list[str]]):
    session = requests.Session()
    retries = Retry(total=5,
                    backoff_factor=1,
                    status_forcelist=[503, 504])
    session.mount("http://", HTTPAdapter(max_retries=retries))

    # Endpoint
    # GET /cves/:cve
    # GET /edbs/:edb
    # POST /multi-cves
    # POST /multi-edbs
    if args[0] in ['cves', 'edbs']:
        path = f'{args[0]}/{args[1][0]}'
        try:
            response_old = requests.get(
                f'http://127.0.0.1:1325/{path}', timeout=(3.0, 10.0)).json()
            response_new = requests.get(
                f'http://127.0.0.1:1326/{path}', timeout=(3.0, 10.0)).json()
        except requests.ConnectionError as e:
            logger.error(
                f'Failed to Connection..., err: {e}, {pprint.pformat({"args": args, "path": path}, indent=2)}')
            exit(1)
        except requests.ReadTimeout as e:
            logger.warning(
                f'Failed to ReadTimeout..., err: {e}, {pprint.pformat({"args": args, "path": path}, indent=2)}')
        except Exception as e:
            logger.error(
                f'Failed to GET request..., err: {e}, {pprint.pformat({"args": args, "path": path}, indent=2)}')
            exit(1)

        diff = DeepDiff(response_old, response_new, ignore_order=True)
        if diff != {}:
            logger.warning(
                f'There is a difference between old and new(or RDB and Redis):\n {pprint.pformat({"args": args, "path": path}, indent=2)}')

            diff_path = f'integration/diff/{args[0]}/{args[1]}'
            with open(f'{diff_path}.old', 'w') as w:
                w.write(json.dumps(response_old, indent=4))
            with open(f'{diff_path}.new', 'w') as w:
                w.write(json.dumps(response_new, indent=4))
    else:
        path = f'{args[0]}'
        k = math.ceil(len(args[1])/5)
        for _ in range(5):
            payload = {"args": random.sample(args[1], k)}
            try:
                response_old = session.post(
                    f'http://127.0.0.1:1325/{path}', data=json.dumps(payload), headers={'content-type': 'application/json'}, timeout=3.0).json()
                response_new = session.post(
                    f'http://127.0.0.1:1326/{path}', data=json.dumps(payload), headers={'content-type': 'application/json'}, timeout=3.0).json()
            except requests.ConnectionError as e:
                logger.error(
                    f'Failed to Connection..., err: {e}, {pprint.pformat({"args": args, "path": path}, indent=2)}')
                exit(1)
            except requests.ReadTimeout as e:
                logger.warning(
                    f'Failed to ReadTimeout..., err: {e}, {pprint.pformat({"args": args, "path": path}, indent=2)}')
            except Exception as e:
                logger.error(
                    f'Failed to GET request..., err: {e}, {pprint.pformat({"args": args, "path": path}, indent=2)}')
                exit(1)

            diff = DeepDiff(response_old, response_new, ignore_order=True)
            if diff != {}:
                logger.warning(
                    f'There is a difference between old and new(or RDB and Redis):\n {pprint.pformat({"args": args, "path": path}, indent=2)}')

                title = uuid.uuid4()
                diff_path = f'integration/diff/{args[0]}/{title}'
                with open(f'{diff_path}.old', 'w') as w:
                    w.write(json.dumps(
                        {'args': args, 'response': response_old}, indent=4))
                with open(f'{diff_path}.new', 'w') as w:
                    w.write(json.dumps(
                        {'args': args, 'response': response_new}, indent=4))


parser = argparse.ArgumentParser()
parser.add_argument('mode', choices=['cves', 'multi-cves', 'edbs', 'multi-edbs'],
                    help='Specify the mode to test.')
parser.add_argument("--sample_rate", type=float, default=0.01,
                    help="Adjust the rate of data used for testing (len(test_data) * sample_rate)")
parser.add_argument(
    '--debug', action=argparse.BooleanOptionalAction, help='print debug message')
args = parser.parse_args()

logger = logging.getLogger(__name__)
stream_handler = logging.StreamHandler()

if args.debug:
    logger.setLevel(logging.DEBUG)
    stream_handler.setLevel(logging.DEBUG)
else:
    logger.setLevel(logging.INFO)
    stream_handler.setLevel(logging.INFO)

formatter = logging.Formatter(
    '%(levelname)s[%(asctime)s] %(message)s', "%m-%d|%H:%M:%S")
stream_handler.setFormatter(formatter)
logger.addHandler(stream_handler)

logger.info(
    f'start server mode test(mode: {args.mode})')

logger.info('check the communication with the server')
for i in range(5):
    try:
        if requests.get('http://127.0.0.1:1325/health').status_code == requests.codes.ok and requests.get('http://127.0.0.1:1326/health').status_code == requests.codes.ok:
            logger.info('communication with the server has been confirmed')
            break
    except Exception:
        pass
    time.sleep(1)
else:
    logger.error('Failed to communicate with server')
    exit(1)

list_path = None
if args.mode in ['cves', 'multi-cves']:
    list_path = f"integration/cveid.txt"
if args.mode in ['edbs', 'multi-edbs']:
    list_path = f"integration/edbid.txt"

if not os.path.isfile(list_path):
    logger.error(f'Failed to find list path..., list_path: {list_path}')
    exit(1)

diff_path = f'integration/diff/{args.mode}'
if os.path.exists(diff_path):
    shutil.rmtree(diff_path)
os.makedirs(diff_path, exist_ok=True)

with open(list_path) as f:
    list = [s.strip() for s in f.readlines()]
    list = random.sample(list, math.ceil(len(list) * args.sample_rate))
    if args.mode in ['multi-cves', 'multi-edbs']:
        diff_response((args.mode, list))
    else:
        with ThreadPoolExecutor() as executor:
            ins = ((args.mode, [e]) for e in list)
            executor.map(diff_response, ins)
