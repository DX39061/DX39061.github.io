# [TODO]pyc、字节码与花指令


## pyc文件简析

### pyc是什么？

当我们在代码中import另外的python文件时，就会生成一个相应的pyc文件（python3会将其放在`__pycache__`文件夹中），这是 `python code object`的持久化储存方式，能够加速下一次的装载，提高运行效率。

