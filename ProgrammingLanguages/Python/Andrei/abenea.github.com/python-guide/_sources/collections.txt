Collections
===========

Membership
----------

To overload the ``in`` operator you can define the :meth:`object.__contains__`
method::

  class PrimaryColors:
      def __init__(self, color1, color2, color3):
          self.color1 = color1
          self.color2 = color2
          self.color3 = color3

      def __contains__(self, color):
          return color in (self.color1, self.color2, self.color3)

  crt = PrimaryColors('red', 'green', 'blue')

  assert 'red' in crt
  assert 'cyan' not in crt


Indexing and Slicing
--------------------

These methods are useful for implementing collections similar to lists and
dictionaries::

  class Indexable:
      def __getitem__(self, key):
          print '__getitem__ called with key', repr(key)

      def __setitem__(self, key, value):
          print '__setitem__ called with key', repr(key), 'and value', repr(value)

      def __delitem__(self, key):
          print '__delitem__ called with key', repr(key)

  a = Indexable()

You can use anything as a key::

  a[0]
  a['test']
  a[set([1, 2])]

The slicing syntax creates :func:`slice` objects::

  a[1:2]
  a[1:10:2]
  a[:3]

Of course, you can call the :func:`slice` function yourself::

  a[slice(1, 2)]
  a[slice(1, 10, 2)]
  a[slice(0, 3)]

The methods :meth:`object.__setitem__` and :meth:`object.__delitem__` receive
the same key argument as :meth:`object.__getitem__`::

  a[0] = 3
  a[1:3] = [1]
  del a[0]
  del a[1:3]

If the class does not support the :ref:`iteration protocol <iteration
protocol>`, :meth:`object.__getitem__` will be called with integer arguments
starting from 0 until the function raises :exc:`exceptions.IndexError`::

  class Cubes:
      def __init__(self, n):
          self.n = n

      def __getitem__(self, key):
          if key >= 0 and key < self.n:
              return key * key * key
          else:
              raise IndexError

  assert [x for x in Cubes(10)] == [0, 1, 8, 27, 64, 125, 216, 343, 512, 729]


Exercise
~~~~~~~~

Implement a dictionary that remembers the order in which the keys were
inserted (see the unit test). The class must start with::

  class OrderedDict:
      def __init__(self):
          self._keys = []
          self._dict = {}

Notes:

- when defining a custom dictionary class you would normally inherit from
  :class:`dict` and get some operators for free, but the purpose of this
  exercise is to implement everything manually
- a dictionary that remembers the insertion order is included in the standard
  library: :class:`collections.OrderedDict`
- two dictionaries are considered equal if they have the same keys (regardless
  of order) and the values for each key are equal.

**Unit test**::

  def test_ordereddict():
      od = OrderedDict()

      # __setitem__
      od['color'] = 'black'
      od['price'] = 99
      od['delay'] = 60

      # __len__
      assert len(od) == 3

      # __contains__
      assert 'color' in od

      # __getitem__
      assert od['color'] == 'black'

      # keys() in insertion order
      assert od.keys() == ['color', 'price', 'delay']

      # __iter__
      assert list(od) == ['color', 'price', 'delay']

      # iteritems() in insertion order
      assert list(od.iteritems()) == \
             [('color', 'black'), ('price', 99), ('delay', 60)]

      # __repr__
      assert repr(od) == "{'color': 'black', 'price': 99, 'delay': 60}"

      # __delitem__
      del od['delay']

      # __eq__
      assert od == {'color': 'black', 'price': 99}

      # __ne__
      assert od != {'color': 'black', 'price': 150}
      assert not od != {'color': 'black', 'price': 99}
