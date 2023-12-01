from unittest import TestCase

from sus.common.fragmentation import Fragmenter


class Test(TestCase):
    def test_fragmenter(self):
        fragger = Fragmenter(150)
        data = b"hello world"
        fragger.add_message(data)
        frag = fragger.fragment()
        self.assertEqual(len(frag), len(data) + 1)

    def test_defragmenter(self):
        self.fail()
