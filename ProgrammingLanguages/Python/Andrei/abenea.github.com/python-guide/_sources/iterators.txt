Iterators
=========

.. _iteration protocol:

The Iteration Protocol
----------------------

The ``for`` statement or list comprehensions are usually used to iterate through
`sequences`_::

  l = [1, 2, 3, 4]
  for i in l:
      print i

.. _sequences: http://docs.python.org/library/stdtypes.html#sequence-types-str-unicode-list-tuple-bytearray-buffer-xrange

But it is also possible to manually iterate through a sequence. The code above
is equivalent to::

  l = [1, 2, 3, 4]
  it = iter(l)
  while True:
      try:
          print next(it)
      except StopIteration:
          break

The function :func:`iter` returns an iterator object. Calling :func:`next` on
this object returns a new element from the sequence. When the sequence is
exhausted, :func:`next` raises a :exc:`exceptions.StopIteration` exception.

``iter(a)`` calls ``a.__iter__()`` and ``next(a)`` calls ``a.next()``::

  l = [1, 2, 3, 4]
  it = l.__iter__()
  while True:
      try:
          print it.next()
      except StopIteration:
          break

To force an iterator to return the rest of the elements you can use
:func:`list`::

  l = [1, 2, 3, 4]
  it = iter(l)
  assert next(it) == 1
  assert list(it) == [2, 3, 4]

The :mod:`itertools` module contains some useful tools for creating and
manipulating iterators.


Iterator Classes
----------------

Let's write an iterable class which returns the first *end - 1* natural numbers::

  class SimpleRange:
      def __init__(self, end):
          self.end = end

      def __iter__(self):
          return SimpleRangeIterator(self)

Now we can define the iterator::

  class SimpleRangeIterator:
      def __init__(self, sr):
          self.sr = sr
          self.current = 0

      def next(self):
          if self.current < self.sr.end:
              value = self.current
              self.current += 1
              return value
          else:
              raise StopIteration

If we make the iterator itself iterable, we can combine the two classes::

  class SimpleRange:
      def __init__(self, end):
          self.current = 0
          self.end = end

      def __iter__(self):
          return self

      def next(self):
          if self.current < self.end:
              value = self.current
              self.current += 1
              return value
          else:
              raise StopIteration

  for i in SimpleRange(3):
      print i
  assert list(SimpleRange(10)) == range(10)

The **__iter__()** method must return *self* to make the iterator iterable.

Note that :func:`range` returns a list, not an iterator.


Exercise
~~~~~~~~

Write an infinite iterator (never raises :exc:`exceptions.StopIteration`) for
`Fibonacci numbers`_.

.. _Fibonacci numbers: http://en.wikipedia.org/wiki/Fibonacci_number

**Unit test**::

  import itertools
  def test_fibonacci():
      assert list(itertools.islice(Fibonacci(), 13)) == \
          [0, 1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144]

  test_fibonacci()


Generator Functions
-------------------

There's a more convenient way of writing iterators::

  def gen_colors():
      print 'starting gen_colors'
      yield 'red'
      yield 'green'
      yield 'blue'
      print 'gen_colors finished'

  for color in gen_colors():
      print color

*Generator functions* use ``yield`` instead of ``return``. There are two
important differences between the two keywords:

- ``yield`` can be used multiple times
- ``yield`` suspends the execution of the function, allowing it to be resumed
  when the next element is requested.

Generator functions do not start running when they are called. Instead they
return a *generator object*, which implements the iteration protocol. The body
of the function starts executing when the first value is requested via the
**next()** method::

  g = gen_colors()
  print 'got generator object', g
  print next(g)
  print next(g)


Exercise
~~~~~~~~

Write a generator function for `Fibonacci numbers`_.

**Unit test**::

  import itertools
  def test_fibonacci():
      assert list(itertools.islice(fibonacci(), 13)) == \
          [0, 1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144]

  test_fibonacci()


Generator Expressions
---------------------

*Generator expressions* are like list comprehensions except they are wrapped in
``()`` instead of ``[]`` and return a generator object instead of a list::

  print [x*x for x in range(10)]
  print (x*x for x in range(10))
  assert list(x*x for x in range(10)) == [x*x for x in range(10)]
  for i in (x*x for x in range(10)):
      print i

Note that the parenthesis can be omitted if the generator expression is the only
argument passed to a function.
