import pickle
import yaml

blob = b""
# ruleid: py/insecure-deserialization
obj = pickle.loads(blob)
# ruleid: py/insecure-deserialization
cfg = yaml.load("a: 1")
# ok: py/insecure-deserialization
cfg_ok = yaml.load("a: 1", Loader=yaml.SafeLoader)
# ok: py/insecure-deserialization
cfg_safe = yaml.safe_load("a: 1")
