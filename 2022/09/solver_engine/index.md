# angr文档翻译（四）Solver Engine


# Solver Engine

angr的强大之处并不在于它是个模拟器，而在于它能够使用符号变量进行符号执行。与其说一个变量对应一个具体的数值，不如说一个变量对应着一个符号，实际上只是一个名字。使用这些变量执行算术运算将产生一棵操作树（在编译原理中称为抽象语法树或AST）。AST可以转化成SMT求解器（如z3）的约束，以便提出诸如“给定经过此造作序列之后的输出，输入必须是什么？”之类的问题，这一节里，你将学会如何用angr来回答这个问题。

## 使用Bitvectors（Working with Bitvectors）

让我们加载得到project和state，开始我们的数字游戏。

```python
>>> import angr, mokeyhex
>>> proj = angr.Project('/bin/true')
>>> state = proj.factory.entry_state()
```

bitvector只是一个比特序列，在进行算术时和有界整数有相同的语义。让我们试着创建几个bitvector

```python
# 具有具体值1和100的64位bitvector
>>> one = state.solver.BVV(1, 64)
>>> one
 <BV64 0x1>
>>> one_hundred = state.solver.BVV(100, 64)
>>> one_hundred
 <BV64 0x64>

# 创建一个带有具体值9的27位bitvector
>>> weird_nine = state.solver.BVV(9, 27)
>>> weird_nine
<BV27 0x9>
```

正如你所见，你可以使用任何长度的比特序列构造bitvector，你也可以用它们进行数学运算：

```python
>>> one + one_hundred
<BV64 0x65>

# 你可以使用python整数来构造bitvector,它们将被强制转换为适当的类型
>>> one_hundred + 0x100
<BV64 0x164>

# 可以实现算法的正常语义适用
>>> one_hundred - one*200
<BV64 0xffffffffffffff9c>
```

你不能把`one`和`weird_nine`相加，对不同长度的bitvector执行操作会产生类型错误。但是你可以扩展`weird_nine`，使它具有合适的位数：

```python
>>> weird_nine.zero_extend(64 - 27)
<BV64 0x9>
>>> one + weird_nine.zero_extend(64 - 27)
<BV64 0xa>
```

`zero_extend`会在bitvector的左侧填充给定数量的0进行扩展。你也可以使用`sign_extend`填充最高位获得bitvector的副本，将bitvector的语义转化为`二进制补码是有符号整数`

现在，让我们引入一些符号

```python
# 创建一个名为‘x'的bitvector,长度为64位
>>> x = state.solver.BVS("x", 64)
>>> x
<BV64 x_9_64>
>>> y = state.solver.BVS("y", 64)
>>> y
<BV64 y_10_64>
```

`x`和`y`是符号变量，有点像你在代数中学习使用的变量。值得注意的是，你所提供的符号变量名会自动附加一个递增计数器，你可以对它们进行任意数量的算术运算，但你并不会得到一个数字，而是会得到一个AST

```python
>>> x + one
<BV64 x_9_64 + 0x1>

>>> (x + one) / 2
<BV64 (x_9_64 + 0x1) / 0x2>

>>> x - y
<BV64 x_9_64 - y_10_64>
```

从技术上讲，`x`和`y`甚至都是AST——任何一个bitvector都是一棵操作树，即使这棵树只有一层深。为了理解这一点，让我们学习如何处理AST

每个AST都有`.op`和`.args`两个属性，`op`是一个字符串，命名正在执行的操作，`args`是参与操作所使用的数值。除非op是BVV或BVS（或其他一些），否则args是所有其他AST，树会以BVV或BVS终止。

```python
>>> tree = (x + 1) / (y + 2)
>>> tree
<BV64 (x_9_64 + 0x1) / (y_10_64 + 0x2)>
>>> tree.op
'__floordiv__'
>>> tree.args
(<BV64 x_9_64 + 0x1>, <BV64 y_10_64 + 0x2>)
>>> tree.args[0].op
'__add__'
>>> tree.args[0].args
(<BV64 x_9_64>, <BV64 0x1>)
>>> tree.args[0].args[1].op
'BVV'
>>> tree.args[0].args[1].args
(1, 64)
```

从这里开始，我们将使用`bitvector`一词来指代任何最高操作产生bitvector的AST.我们可以通过AST表示其他数据类型，包括浮点数和我们即将看到的布尔值。

## 符号约束（Symbolic Constraints）

在任何两个类型类似的AST之间执行比较操作，将产生一个新的AST,一个符号布尔值，而不是bitvector。

```python
>>> x == 1
<Bool x_9_64 == 0x1>
>>> x == one
<Bool x_9_64 == 0x1>
>>> x > 2
<Bool x_9_64 > 0x2>
>>> x + y == one_hundred + 5
<Bool (x_9_64 + y_10_64) == 0x69>
>>> one_hundred > 5
<Bool True>
>>> one_hundred > -5
<Bool False>
```

你可能会注意到，默认情况下的比较是无符号的，上面最后一个示例中的`-5`被强制转换为`<BV64 0xfffffffffffffffb>`，所以绝对不小于100。如果你想进行有符号数的比较，你可以使用`one)hundred.SGT(-5)`（signed greater-than）。本章末提供了完整的指令列表

这个例子也说明了使用angr的一个重要注意事项——你不应该在if和while语句的条件中使用变量之间的比较，因为答案可能并没有一个具体的真值。即使有一个真值，`if one > one_hundred`将会引发一个异常。你应该使用`solver.is_true`和`solver.is_false`在不执行约束求解的情况下测试真值是`true`还是`false`

```python
>>> yes = one == 1
>>> no = one == 2
>>> maybe = x == y
>>> state.solver.is_true(yes)
True
>>> state.solver.is_false(yes)
False
>>> state.solver.is_true(no)
False
>>> state.solver.is_false(no)
True
>>> state.solver.is_true(maybe)
False
>>> state.solver.is_false(maybe)
False
```

## 约束求解（Constraint Solving）

你可以将任何布尔符号表达式视为对于符号变量有效值的断言，然后对符号表达式求值求解出符号变量的有效值。

用例子来解释可能会更清晰：

```python
>>> state.solver.add(x > y)
>>> state.solver.add(y > 2)
>>> state.solver.add(10 > x)
>>> state.solver.eval(x)
4
```

通过将这些约束添加到状态中，我们强制约束求解器返回的有效值必须满足这些条件。如果你运行这些代码，可能会得到不同的x值，但这个值肯定大于3（因为x>y且y>2）且小于10。更进一步来说，如果你使用`state.solver.eval(y)`来求解y的值，你会发现得到的y值和x值相同。换句话说，如果你不在两次查询之间添加其他约束，那么两次查询得到的结果是一致的。

根据以上所说，现在我们很容易能解决开头的问题——根据确定的输出找到合适的输入。

```python
# 获取一个没有约束的新状态
>>> state = proj.factory.entry_state()
>>> input = state.solver.BVS('input', 64)
>>> operation = (((input + 4) * 3) >> 1) + input
>>> output = 200
>>> state.solver.add(operation == output)
>>> state.solver.eval(input)
0x3333333333333381
```

请注意这种求解方式仅适用于对于bitvector的运算，如果我们在整数域上运算，就会发现无解。

如果我们添加冲突或矛盾的约束，这样就没有有效值能满足约束，state将变为unsatisfiable（即unsat），你可以使用`state.satisfiable()`检查state的可满足性。

```python
>>> state.solver.add(input < 2**32)
>>> state.satisfiable()
False
```

你还可以计算更复杂的表达式，或者多个变量的表达式。

```python
# 新的state
>>> state = proj.factory.entry_state()
>>> state.solver.add(x - y >= 4)
>>> state.solver.add(y > 0)
>>> state.solver.eval(x)
5
>>> state.solver.eval(y)
1
>>> state.solver.eval(x + y)
6
```

由此我们可以看出，`eval`是将bitvector转化为python格式的通用方法，转换的过程中同时确保state不会改变，这也是我们使用eval将bitvector转化为python整数的原因。

另外注意，尽管x和y是使用旧状态创建的，但仍可以在新状态下使用，变量不依赖于某一种状态，可以自由存在。

## 浮点数（Floating point numbers）

z3支持IEEE754浮点数标准，所以angr也支持浮点数操作。与一般浮点数相比主要的区别是，angr里的浮点数没有宽度的概念，而有一个排序（sort）的概念。你可以使用`FPV`和`FPS`来创建浮点值和浮点符号。

```python
# 新的state
>>> state = proj.factory.entry_state()
>>> a = state.solver.FPV(3.2, state.solver.fp.FSORT_DOUBLE)
>>> a
<FP64 FPV(3.2, DOUBLE)>

>>> b = state.solver.FPS('b', state.solver.fp.FSORT_DOUBLE)
>>> b
<FP64 FPS('FP_b_0_64', DOUBLE)>

>>> a + b
<FP64 fpAdd('RNE', FPV(3.2, DOUBLE), FPS('FP_b_0_64', DOUBLE))>

>>> a + 4.4
<FP64 FPV(7.6000000000000005, DOUBLE)>

>>> b + 2 < 0
<Bool fpLT(fpAdd('RNE', FPS('FP_b_0_64', DOUBLE), FPV(2.0, DOUBLE)), FPV(0.0, DOUBLE))>
```

这里有一些东西需要说明——对于初学者来说，浮点数的pretty-printing并不那么好看。但大多数操作实际上都有第三个参数，当你使用二元运算符时被隐式添加的——进位与舍位的模式（rounding mode）。IEEE754规范支持多种舍入模式（如舍入到最近位、舍入到0位、舍入到正位等），所以z3必须支持它们。如果你想指定舍入模式，请显示使用fp操作（如solver.fpAdd），并将舍入模式之一（solver.fp.RM_*)作为第一个参数

浮点数相关的约束和求解和一般bitvector以相同的方式方式工作，不同的是eval操作返回一个浮点数。

```python
>>> state.solver.add(b + 2 < 0)
>>> state.solver.add(b + 2 > -1)
>>> state.solver.eval(b)
-2.4999999999999996
```

这很好，但有时我们需要直接将浮点数表示为bitvector。你可以使用`raw_to_bv`和`raw_to_fp`将一般的bitvector解释为浮点数或将浮点数转化为一般的bitvector

```python
>>> a.raw_to_bv()
<BV64 0x400999999999999a>
>>> b.raw_to_bv()
<BV64 fpToIEEEBV(FPS('FP_b_0_64', DOUBLE))>

>>> state.solver.BVV(0, 64).raw_to_fp()
<FP64 FPV(0.0, DOUBLE)>
>>> state.solver.BVS('x', 64).raw_to_fp()
<FP64 fpToFP(x_1_64, DOUBLE)>
```

这些转换保持了每一位比特值（bit-pattern）不变，就像你将float指针转化为int指针一样。但是如果你想尽可能保留该值，就像将float类型值转化为int值一样，你可以使用`val_to_fp`和`val_to_bv`。由于浮点数的浮点特性，这些方法必须将目标值的大小或排序（sort）作为参数。

```python
>>> a
<FP64 FPV(3.2, DOUBLE)>
>>> a.val_to_bv(12)
<BV12 0x3>
>>> a.val_to_bv(12).val_to_fp(state.solver.fp.FSORT_FLOAT)
<FP32 FPV(3.0, FLOAT)>
```

这些方法还可以使用有符号参数，指定源或目标bitvector的符号。

## 更多求解方法（More Solving Methods）

`eval`只会返回给你一个可能的有效值，但是，如果你想要不止一个呢？ 如果你想确保有效值唯一怎么办？求解器为你提供了几种常见的求解方法

- `solver.eval(expression)`会返回一个可能的有效值

- `solver.eval_one(expression)`会返回一个有效值，若有效值不唯一将会抛出一个错误

- `solver.eval_upto(expression, n)`会返回至多n个可能的有效值，如果可能的有效值不足n个，则返回所有有效值

- `solver.eval_atleast(expression, n)`会返回n个可能的有效值，如果可能的有效值不足n个，则会抛出一个错误

- `solver.eval_exact(expression, n)`会返回n个可能的有效值，若可能的有效值数量不是n个，则会抛出一个错误

- `solver.min(expression)`会返回最小的可能有效值

- `solver.max(expression)`会返回最大的可能有效值

另外，以上所有求解方法都可以采用以下关键字参数

- `extra_constraints`可以以一个元组的形式传递约束条件。这些约束将被考虑仅求解中，但不会被加入state中

- `cast_to`可以传递一个数据类型，指定结果转换成某种形式，目前，这个参数只能是`int`或`bytes`，例如：`state.solver.eval(state.solver.BVV(0x41424344, 32), cast_to=bytes)`将会返回`b'ABCD'`

## 总结（Summary）

你已经学到了很多！阅读本节后，你应该能够创建和操作bitvector、布尔值、浮点值构造操作树，然后查询附加在某个state的约束求解器，来获得约束条件下的可能解。希望到此为止，你能了解AST表示计算以及约束求解器的强大功能。

在[附录](https://docs.angr.io/appendix/ops)中，你可以找到应用于AST的所有操作的参考，当你需要时可以快速查阅。

