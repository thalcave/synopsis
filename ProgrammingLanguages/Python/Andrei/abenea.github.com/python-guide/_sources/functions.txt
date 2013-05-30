Functions
=========

Scopes
------

Creating Names
~~~~~~~~~~~~~~

To create new variables you don't need declarations, only assignments. But how
does Python determine the scope of the variable?

There is a *global scope* for each file. Each function has it's own *local
scope*::

  x = 1
  def f():
      x = 2
      print x

  f()
  print x

Assignment isn't the only way to add names to a scope. You can also use
``import``, ``def`` or function argument lists. To get the list of names from
the current scope, you can use the :func:`dir` function::

  import math
  x = 1
  def f(arg):
      x = 2
      print 'x =', x
      print 'local scope:', dir()

  f(3)
  print 'x =', x
  print 'global scope:', dir()

Notice how the names **f** and **math** are created in the global scope and
**arg** is created in the local scope. **x** is present in both scopes, but with
different values.

But if assignments from a function create new names in the local scope, how can
we change the global variables from a function? The variable must be declared as
``global``::

  def f():
      global x
      x = 2
      print x

  x = 1
  f()
  print x


Name Resolution
~~~~~~~~~~~~~~~

In the previous example you can notice that **x** is created after the body of
**f** has been defined. This proves that name resolution happens when **f** is
called. Names declared as ``global`` don't even need to exist in the global
scope when the function is executed (you can even remove the ``x = 1``
assignment).

For name lookup the ``global`` declaration is not needed, as long as there is no
local variable with the same name::

  x = 1
  def f():
      print x

  f()

But if a function contains a statement defining a name in the local scope, that
name is considered local for all the lookups, even for those that appear before
the assignment. This is true even for unreachable statements which define
names::

  x = 1
  def f():
      print x
      # error: local variable 'x' referenced before assignment
      if False:
          x = 2

  f()

More formally, names are searched in:

- the local scope of the current function, see :func:`locals`
- the local scopes of enclosing functions
- the global scope, see :func:`globals`
- the built-in scope, run ``dir(__builtins__)``

The search stops at the first place where the name is found. Each one of these
places is essentially a dictionary which maps variable names (strings) to
objects. Assignment is equivalent to changing this dictionary::

  def f(a):
      print 'f begins:', locals()
      a = 2
      b = 3
      print 'f ends  :', locals()

  t = 1
  f(t)
  print 'globals :', globals()


Argument Passing
~~~~~~~~~~~~~~~~

Why did **t** remain unchanged?

Arguments are passed using the same mechanism as assignment. Imagine the Python
interpreter executes the following pseudocode for the previous example::

  globals['t'] = 1

  f_frame = new_stack_frame()
  interpreter_stack.push(f_frame)
  f_frame.locals['a'] = globals['t']

  print 'f begins:', locals()
  f_frame.locals['a'] = 2
  f_frame.locals['b'] = 3
  print 'f ends  :', locals()

  interpreter_stack.pop()

  print 'globals :', globals()

This means that mutable arguments (for example lists) can be modified, but it is
not possible to make a non-local name point to another object simply by
assigning to an argument::

  l = [1]

  def f(l):
      l = [1, 2]

  f(l)
  print 'after f:', l

  def g(l):
      l.append(3)

  g(l)
  print 'after g:', l

.. _nested functions:

Nested Functions
----------------

::

  def f1(x):
      def f2():
          print x
      return f2

  action = f1(1)
  action()

  f1(2)()
  f1(3)()

Notice that **f2** can access the **x** even if after **f1** (which defines
**x**) has returned. This type of function is called `closure
<http://en.wikipedia.org/wiki/Closure_(computer_science)>`_. Simply put, the
function `f2` holds a reference to the local scope in which it was defined.

Unfortunately there is no way to change the value of **x** from **f2** in
Python 2. Python 3 fixes this by adding the `nonlocal
<http://docs.python.org/py3k/reference/simple_stmts.html#the-nonlocal-statement>`_
statement. However this can be worked around easily::

  def incrementer(step=1):
      v = dict(x=0)
      def inner():
          v['x'] += step
          return v['x']
      return inner

  a = incrementer()
  print a()
  print a()
  print a()

  b = incrementer(5)
  print b()
  print b()
  print b()

Notice how each call to **incrementer** creates a new scope (**b** starts
counting from 0 again).


Exercise
~~~~~~~~

Let's say you want to add some logging to your application. You have some
functions already written, and want to log the arguments for each function
call::

  def a(color, size=5):
      pass

  def b(l):
      pass

  def c(arg1, arg2, arg3):
      pass

  a('black')
  b(["a", 1])
  c('test', 4, arg3=51)

Of course, you could go through each function and add a logging statement::

  import logging
  logging.basicConfig(level=logging.DEBUG)

  def a(color, size=5):
      logging.debug("calling a(%s, %d)" % (repr(color), size))

  def b(l):
      logging.debug('calling b(%s)' % repr(l))

  def c(arg1, arg2, arg3):
      logging.debug('calling c(%s, %s, %s)'
                    % (repr(arg1), repr(arg2), repr(arg3)))

  a('black')
  b(["a", 1])
  c('test', 4, arg3=51)

However, this gets boring fast. There's a better way to do it: write a function

.. function:: log_call(f)

which returns a function that does the required logging and then calls
**f**. You can then replace the original functions (ex: ``a = log_call(a)``)
before calling them to achieve the desired result.

Hints:

- you might need to revisit the last example from :ref:`mappings`
- to get the original name of **f** you can use ``f.__name__``

Expected output::

  DEBUG:root:calling a('black')
  DEBUG:root:calling b(['a', 1])
  DEBUG:root:calling c('test', 4, arg3=51)


Function Decorators
-------------------

Python provides some syntactic sugar to make wrapping functions (which was
necessary in the previous exercise) easier. Let's say you defined a function::

  def wrap(f):
      ...

Instead of this::

  def f():
      ...
  f = wrap(f)

you can use this syntax::

  @wrap
  def f():
      ...

In the simplest form, a decorator is a function which takes as argument a
function to be decorated and returns another function.

The ``@`` syntax calls the decorator with the function from the following line
and binds the name of this function to the return value of the call.

You can also nest decorators::

  @a
  @b
  @c
  def f():
      ...

is equivalent to::

  def f():
      ...
  f = a(b(c(f)))

If you want to pass arguments to a decorator, you must write a function which
takes those arguments and return another function that acts as a decorator
without arguments::

  def decorator_with_args(a, b):
      def decorator_without_args(f):
          ...
      return decorator_without_args

Now you can write::

  @decorator_with_args(1, 2):
  def f():
      ...

which means::

  def f():
      ...
  f = decorator_with_args(1, 2)(f)

To achieve something useful, the decorator usually needs to return a different
function::

  def logging_decorator(f):
      def wrapper(*args, **kwargs):
          print "before"
          ret = f()
          print "after"
          return ret
      return wrapper

  @logging_decorator
  def hi():
      print "hi"

  hi()
  print hi.__name__

Notice that ``hi.__name__`` is now ``wrapper``. We can fix this by using
:func:`functools.wraps`::

  from functools import wraps

  def logging_decorator(f):
      @wraps(f)
      def wrapper(*args, **kwargs):
          print "before"
          ret = f()
          print "after"
          return ret
      return wrapper

  @logging_decorator
  def hi():
      print "hi"

  hi()
  print hi.__name__


Exercise
~~~~~~~~

Starting from the :func:`log_call` function from the previous exercise, define

.. function:: time_call(level=logging.DEBUG)

which is a decorator that does everything :func:`log_call` did, but also:

- uses :func:`time.clock()` to log timing information
- uses :func:`functools.wraps`

Usage example::

  @time_call()  # notice the parentheses; why are they required?
  def f():
      pass

  @time_call(logging.INFO)
  def square(n):
      return len([(x, y) for x in range(n) for y in range(n)])

  print f()
  print square(700)
  print square.__name__

Expected output::

  DEBUG:root:calling f(): 0.0s
  None
  INFO:root:calling square(700): 0.34s
  490000
  square
