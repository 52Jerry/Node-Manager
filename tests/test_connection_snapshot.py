import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

module_path = Path(__file__).resolve().parents[1] / 'node-manager/singbox/connection_snapshot.py'
spec = importlib.util.spec_from_file_location('connection_snapshot', module_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ConnectionSnapshotTests(unittest.TestCase):
    def test_ten_thousand_queries_parse_each_file_once(self):
        with tempfile.TemporaryDirectory() as directory:
            config, registry = Path(directory)/'config.json', Path(directory)/'users.json'
            config.write_text('{}'); registry.write_text('{}')
            users = [{'name':f'user-{i}','uuid':str(i)} for i in range(10000)]
            inbound = {'tag':'vless','users':users}
            load_config = Mock(return_value={'inbounds':[inbound]})
            load_registry = Mock(return_value={'users':{}})
            cache = module.ConnectionSnapshotCache()
            for i in range(10000):
                value = cache.get(config, registry, load_config, load_registry)
                self.assertEqual(value.find(inbound,{f'user-{i}'})['uuid'], str(i))
            self.assertEqual(load_config.call_count, 1)
            self.assertEqual(load_registry.call_count, 1)

    def test_atomic_replacement_invalidates_even_same_length(self):
        with tempfile.TemporaryDirectory() as directory:
            config, registry = Path(directory)/'config.json', Path(directory)/'users.json'
            config.write_text('{}'); registry.write_text('{"access":true }')
            loader = Mock(side_effect=[{'inbounds':[]}, {'inbounds':[]}])
            read_registry = lambda: json.loads(registry.read_text())
            cache = module.ConnectionSnapshotCache()
            self.assertTrue(cache.get(config,registry,loader,read_registry).registry['access'])
            replacement = registry.with_suffix('.tmp')
            replacement.write_text('{"access":false}')
            replacement.replace(registry)
            self.assertFalse(cache.get(config,registry,loader,read_registry).registry['access'])
            self.assertEqual(loader.call_count, 2)

    def test_changed_invalid_file_fails_closed_without_old_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            config, registry = Path(directory)/'config.json', Path(directory)/'users.json'
            config.write_text('{}'); registry.write_text('{}')
            read_config = lambda: json.loads(config.read_text())
            read_registry = lambda: json.loads(registry.read_text())
            cache = module.ConnectionSnapshotCache()
            cache.get(config,registry,read_config,read_registry)
            registry.write_text('invalid-json')
            with self.assertRaises(ValueError):cache.get(config,registry,read_config,read_registry)

    def test_aliases_preserve_first_inbound_match_and_socks_username(self):
        inbound={'users':[{'name':'old','username':'public'},{'name':'new'}]}
        value=module.ConnectionSnapshot({'inbounds':[inbound]}, {})
        self.assertEqual(value.find(inbound,{'old','new'})['name'],'old')
        self.assertEqual(value.find(inbound,{'public'},'username')['name'],'old')
        self.assertIsNone(value.find(inbound,{'missing'}))


if __name__ == '__main__':unittest.main()
