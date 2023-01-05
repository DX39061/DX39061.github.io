# 春秋杯冬季赛godeep wp


这场比赛唯一有意义的一道逆向题，需要熟悉idapython的api，并要求一定数据结构知识，在这贴几个脚本方便以后可能用到

整个题目就是在探索路径，动调得知`main_convert`会把输入转换成二进制01数组，然后根据01走相应的分支，一个点往后对应两条路，相当于要建一个二叉树

给节点改个名先

```python
start = 0x401000
end = 0x583400
index = 0
for i in range(start, end):
    if "godeep_tree." in get_name(i):
        set_name(i, "node"+str(index))
        index += 1
```

总共5672个节点，获取所有节点和边

```python
from idaapi import *
from idc import *
start = 0x401000
end = 0x583400
out = open("out.txt", "w")

for i in range(start, end):
    parent = get_name(i)
    if parent[0:4] != "node":
        continue
    out.write(parent[4:]+" ")
    j = i
    f = False
    child = GetDisasm(j)
    last = ""
    while child != "retn":
        if last == child:
            j += 1
            child = GetDisasm(j)
            continue
        if child == 'call    node5672':
            if f:
                out.write(child[child.find('e')+1:] +" ")
            else:
                f = True
        elif 'call    node' in child:
            out.write(child[child.find('e')+1:]+" ")
        elif 'wrong' in child:
            out.write("wrong ")
        elif 'right' in child:
            out.write("right ")
        last = child
        j += 1  
        child = GetDisasm(j)
    out.write('\n')
```

建立二叉树+dfs求路径

```python
from Crypto.Util.number import *
file = open("out.txt", "r")
dic = dict()
class TreeNode:
    def __init__(self, id):
        self.id = id
        self.state = True
        self.flag = False
        self.left = None
        self.right = None

root = TreeNode(9999)
node0 = TreeNode(0)
root.left = node0
dic[0] = node0

for i in file.readlines():
    parent = eval(i.split()[0])
    parent_node = TreeNode(parent)
    if dic.get(parent) != None:
        parent_node = dic.get(parent)
    else:
        dic[parent] = parent_node

    if i.split()[1] == 'wrong':
        parent_node.state = False
        continue
    if i.split()[1] == 'right':
        parent_node.flag = True
        continue
    if len(i.split()) == 2:
        left_node = TreeNode(eval(i.split()[1]))
        dic[eval(i.split()[1])] = left_node
        parent_node.left = left_node
    elif len(i.split()) == 3:
        left_node = TreeNode(eval(i.split()[1]))
        dic[eval(i.split()[1])] = left_node
        parent_node.left = left_node
        right_node = TreeNode(eval(i.split()[2]))
        dic[eval(i.split()[2])] = right_node
        parent_node.right = right_node

path = []
def dfs(parent):
    if parent.flag:
        print(path)
        print(long_to_bytes(eval("0b"+"".join(str(i) for i in path).removeprefix('1'))))
        exit()
    if not parent.state:
        return
    if parent.left:
        path.append(1)
        dfs(parent.left)
        path.pop(-1)
    if parent.right:
        path.append(0)
        dfs(parent.right)
        path.pop(-1)
dfs(root)
print("no answer")
print(path)
```

flag{fc03bd97-ff7b-419f-8987-78bc745d3b0a}

