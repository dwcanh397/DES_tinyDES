import random
import threading
import unittest
from core.tinydes import generate_subkeys_from_key, tinyDES_encrypt_block, tinyDES_decrypt_block
from core.des import generate_des_subkeys, des_process_block, des_bytes
from gui import cipher_library as lib


class Tests(unittest.TestCase):
    def test_known_vector(self):
        c, error = lib.group_one_block('0123456789ABCDEF', '133457799BBCDFF1', 0)
        self.assertIsNone(error)
        self.assertEqual(c, '85E813540F0AB405')
        self.assertEqual(lib.group_one_block(c, '133457799BBCDFF1', 1)[0], '0123456789ABCDEF')

    def test_all_tinydes_keys_and_blocks(self):
        for k in range(256):
            keys, _ = generate_subkeys_from_key(f'{k:08b}')
            outputs = set()
            for b in range(256):
                p = f'{b:08b}'
                c, _ = tinyDES_encrypt_block(p, keys)
                outputs.add(c)
                self.assertEqual(tinyDES_decrypt_block(c, keys)[0], p)
            self.assertEqual(len(outputs), 256)

    def test_independent_des(self):
        if lib.StandardDES is None:
            self.skipTest('Cần PyCryptodome cho kiểm thử độc lập')
        rng = random.Random(2026)
        for _ in range(100):
            k = rng.getrandbits(64).to_bytes(8, 'big')
            p = rng.getrandbits(64).to_bytes(8, 'big')
            expected = lib.StandardDES.new(k, lib.StandardDES.MODE_ECB).encrypt(p)
            self.assertEqual(lib.group_one_block(p.hex(), k.hex(), 0)[0], expected.hex().upper())

    def test_bytes_padding(self):
        k = b'12345678'
        for p in [b'', b'a', b'1234567', b'12345678', b'123456789',
                  'Tiếng Việt: mã hóa và giải mã 🔑\n'.encode(), bytes(range(256))]:
            c = des_bytes(p, k)
            self.assertEqual(des_bytes(c, k, True), p)
            if lib.StandardDES is not None:
                self.assertEqual(c, lib.standard_des(p, k, False))
        bad, _ = lib.group_one_block('0000000000000000', k.hex(), 0)
        with self.assertRaises(ValueError):
            des_bytes(bytes.fromhex(bad), k, True)

    def test_validation_and_text(self):
        for bad in ['', ' ', 'G'*16, '0'*15, 'é']:
            result, error = lib.des_text(bad.encode(), b'12345678', 1, False)
            self.assertIsNone(result)
            self.assertTrue(error)
        for bad in ['', '1'*7, '2'*8]:
            with self.assertRaises(ValueError):
                generate_subkeys_from_key(bad)
        p = 'Đây là văn bản tiếng Việt.'.encode()
        c, _ = lib.des_text(p, b'12345678', 0, False)
        restored, _ = lib.des_text(c['output'].encode(), b'12345678', 1, False)
        self.assertEqual(restored['raw_output'], p)
        trace, _, _ = lib.tinydes_run('5C', '9E', 0)
        self.assertIn('9E', lib.tinydes_bruteforce('5C', f'{trace.out:02X}')[0])

    def test_search_cancel(self):
        result, error = lib.des_bruteforce('0123456789ABCDEF', '133457799BBCDFF1', 8)
        self.assertIsNone(error)
        self.assertEqual(result['tried'], 256)
        self.assertGreater(result['found_count'], 0)
        self.assertEqual(lib.group_one_block('0123456789ABCDEF', result['found_key'], 0)[0], result['ciphertext'])
        cancel = threading.Event()
        cancel.set()
        result, _ = lib.des_bruteforce('0123456789ABCDEF', '133457799BBCDFF1', 20, cancel)
        self.assertTrue(result['cancelled'])
        self.assertEqual(result['tried'], 0)


if __name__ == '__main__':
    unittest.main()
