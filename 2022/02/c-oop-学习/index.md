# C++ OOP 学习笔记


# 变量定义

### - auto

- 由编译器根据上下文自动确定变量的类型

```cpp
auto i = 3;    //i是int型变量
auto k = 4.0f;  //k是float型变量
```

### - 指针变量的动态生成与删除

```cpp
int* ptr = new int;       //单个变量
int* array = new int[10];    //10元素数组
delete ptr;        //删除指针变量所指的单个内存单元
delete[] ptr        //删除多个内存单元组成的内存块
```

### - 左值引用

- 具名变量的别名：类型名 & 引用名 变量名

```cpp
int v0; int & v1 = v0 //v1是v0的别名，它们是内存中是同一单元的两个不同名字
```

- 引用变量必须在定义时初始化（赋初值）

- 被引用变量可以是结构变量成员，如s.m

- 函数参数可以是引用类型，表示函数的形参和实参是同一个变量，改变形参将改变实参
  
  ```cpp
  void swap（int & a; int & b){
      int temp = b;
      b = a;
      a = temp;
  }
  ```

- 函数返回值可以是引用类型，但不能是临时变量（函数内部定义）

### - 右值引用

- 不能取地址，没有名字的就是右值

- 匿名变量（临时变量）的别名：类型名 && 引用名 表达式
  
  ```cpp
  int && sum = 3 + 4;
  float && res = ReturnRvalue(f1,f2);
  ```

- 函数参数引用，减少临时变量拷贝的开销
  
  ```cpp
  void AcceptRvalueRef(T && s){……}
  ```

# 变量的初始化、类型推导与基于范围的循环

### - 初始化列表

```cpp
int a[] = {1,3,5};
int a[] {1,3,5};    //c++11支持
```

### - 初始化变量

```cpp
int a = 3+5;
int a = {3+5};
int a (3+5);
int a {3+5};    //以上全部等效
int* i = new int (10);    //int* i =new int *
double* d = new double{1.2f}; //同上，赋初值
```

### - 类型推导

使用decltype可以对变量或表达式结果的类型进行推导

```cpp
struct{char* name;} anon_u;
struct{
    int d;
    decltype(anon_u) id;
} anon_s[100];
int main(){
    decltype(anon_s) as;
    cin>>as[0].id.name;
    ……
}
```

### - 基于范围的循环

```cpp
int main(){
    int arr[3] = {1,2,3};
    for(int e : arr) //auto e也可以
        cout<<e;
    return 0;
}
```

# 函数重载

- 同名函数两种实现，必须保证参数不同，返回值，参数名称不能作为区分标准

```cpp
void print(char* msg){
    cout<<msg<<endl;
}
void print(int score){
    cout<<score<<endl;
}
int main(){
    print("Hello");
    print(1);
    return 0;
}
```

# 函数参数缺省值与追踪返回类型的函数

### - 函数参数缺省值（默认值）

- 缺省值必须从最后一个开始向前排列

```cpp
void print(char* msg = "hello"){
    cout<<msg<<endl;
}
int main(){
    print("Beijing...");
    print();
    return 0;
}//输出Beijing...hello
```

### -追踪返回类型的函数

```cpp
int func(char* ptr, int val);    //普通函数声明
auto func(char* ptr, int val)->int;    //追踪返回类型的函数声明
auto func(char* ptr, int val)->decltype(……)    //常用方法
```

# 类的定义

### - 基本概念

- 用户自定义的类型，包含函数与数据的特殊“结构体”，称为“对象”

- 类中包含的函数，称为“成员函数”，数据称为“数据成员”

- 类中函数既可以在类中定义，也可以在类外给出定义（类名::函数名，其中::称为“域运算符）
  
  ```cpp
  class Matrix{
      public:
              void fill(char dir){
                      ……;    //在类中定义成员函数
              }
  };
  ------------------------------------------------------------
  void Matrix::fill(char dir){
      ……;    //在类外定义成员函数
  }
  ```

- 类的成员（数据、函数）可以根据需要分成组，不同组设置不同的访问权限

- 权限种类：public、private、protected

### - This指针

- 指向当前对象的指针变量

```cpp
class Matrix{
    public:
            void fill{
                ……
                this->data[0][0] = 1;
                //data[0][0] = 1; 二者等价
            }
};
```

# 

# 类的访问权限与友元

### - 类成员的访问权限

- class中成员缺省属性为private

```cpp
class Matrix{
    public：
            void fill(char dir);
    private:
            int data[6][6];
};
//等价于
class Matrix{
    int data[6][6];
public：
    void fill(char dir);
};
```

- 在类的外部不能用`.`操作符访问对对象的私有成员或保护成员，只能访问公有属性

```cpp
int main(){
    Matrix obj;          //定义变量（对象）
    obj.fill('u');        //访问公有成员
    obj.data[1][1] = 23;    //Error！不能访问私有成员
    return 0;
}
```

- 保护成员（protected）可以在派生类（即子类）中访问

### - 友元

- 可以通过声明函数为类的`友元`来实现访问对象的私有成员

```cpp
class Test{
    int id;
public:
    friend void print(Test obj);
};
void print(Test obj){
    cout<<obj.id<<endl;
}
```

# 构造函数与析构函数

### - 构造函数

- 由编译器自动生成调用语句，用于对象数据成员的初始化，以及其他初始化工作

- 构造函数没有返回值类型，函数名与类名相同

- 类的构造函数可以重载，即可以使用不同的函数参数进行对象初始化

```cpp
class Student{
    long ID;
public:
    Student(long id){ID = id;}
    Student(int year, int order){
            ID = year * 10000 + order;
    }
};
```

- 默认构造函数
  
  - 若未提供构造函数，则编译器自动生成不带任何参数的构造函数
  
  - 在定义元素为对象的数组（ClassName array_var[NUM];）时，类必须提供构造函数

- 构造函数的初始化列表
  
  - 在`()`之后，`{`之前，以`：`开头，使用`数据成员（初始值）`的形式

```cpp
class Student{
    long ID;
public:
    Student(long id):ID(id){}
    Student(int year,int order){
        ID = year * 10000 +order;
    }
};
```

- 在构造函数中调用其他构造函数（委派构造函数）

```cpp
class Info{
public:
    Info() {Init();}
    Info(int i) : Info() {id = i;}
    Info(char c) : Info() {gender = c;}
private:
    void Init() {……}
    int id {2016};
    char gender {'M'};
};
```

### - 析构函数

- 一个类只有一个析构函数，名称是`～类名`，没有函数返回值，没有函数参数

- 编译器在对象生命期结束后自动调用析构函数， 以便释放对象占用的资源

```cpp
class ClassRoom{
    int num;
    long* ID_list;
public:
    ClassRoom() : num(0), ID_list(0) {}
    ……
    ~ClassRoom(){
        if(ID_list) delete[] ID_list;
    }
};
```

### - 拷贝构造函数

- 函数调用时以类的对象为形参或返回类的对象时，编译器自动生成调用`拷贝构造函数`，在已有对象基础上生成新对象

- 拷贝构造函数是一种特殊的构造函数，它的参数是语言规定的，是同类对象的常量引用

```cpp
class Person{
    int id;
    ……
public:
    Person(const Person& src) { id = src.id; ……}
    ……
};
```

# 运算符重载

### - 赋值运算符重载

```cpp
ClassName& operator= (const ClassName& right){
    if (this != &right){   //避免自己赋值给自己
        //将right对象中的内容复制到当前对象中
    }
    return *this;
}
```

### - 流运算符重载

- 重载函数的声明（作为友元）

```cpp
class Test{
    int id;
public:
    friend istream& operator>> (istream& in, Test& dst);
    friend ostream& operator<< (ostream& out, const Test& src);
};
```

- 重载函数实现

```cpp
istream& operator>> (istream& in, Test& dst){
    in >> dst.id;
    return in;
}
ostream& operator<< (ostream& out, Test& src){
    out << src.id << endl;
    return out;
}
```

### - 函数运算符`()`重载

- 重载函数实现

```cpp
ReturnType operator() (Parameters){
    ……
}
className obj;
obj(Real_parameters);
//obj.operator() (Real_parameters);
```

- 重载示例

```cpp
class Test{
public:
    int operator() (int a, int b){
        return a + b;
    }
};
int main(){
    Test sum;
    cout<<sum(1,2);
    return 0;
}
```

### - 下标运算符`[]`重载

- 重载函数返回类型
  
  - 若是引用，则可出现在等号左边，即`obj[index]=value`
  
  - 若不是引用，则只能出现在等号右边，即`var=obj[index]`

- 重载函数示例

```cpp
#include<iostream>
#include<string> //strcmp
using namespace std;

char week_name[7][4] = {"mon", "tu", "wed", "thu", "fri", "sat", "sun"};
class WeekTemp{
    int temp[7];
public:
    int& operator[] (const char* name){
        for(int i = 0; i < 7; i++){
            if (strcmp (week_name[i], name) == 0) return temp[i];
        }
    }
};
int main(){
    WeekTemp beijing;
    beijing["mon"] = -3;
    beijing["tu"] = -1;
    return 0;
}
```

### - 自增减运算符`++--`重载

- 前缀运算符重载声明

```cpp
ReturnType operator++()
ReturnType operator--()
```

- 后缀运算符重载声明

```cpp
ReturnType operator++(int dummy);//dummy为哑元，无实际意义，只为区分
ReturnType operator--(int dummy);
```

# 静态成员与常量成员

### - 静态成员

- 以`static`修饰的数据成员，属于类，被所有对象共享

- 为静态数据赋初值`Type ClassName::static_var = value;`

- 返回值类型前面加上static修饰的成员函数，不能调用非静态成员函数，没有this指针

- 类的静态成员（数据，函数）既可以通过对象访问，也可以通过类名来访问

### - 常量成员

- 以`const`修饰的数据成员，在对象的整个生命周期中不可更改

- 只能在构造函数的初始化列表中被设置，不允许在函数体中通过赋值来设置

- 用const修饰成员函数，则该成员函数在实现时不能有改变对象状态（内容）的语句

- 若对象被定义为常量，则它只能调用以const修饰的成员函数，普通函数不允许调用

# 移动（拷贝）构造函数

- 用来“偷”临时变量"的资源，没有名字如返回值等的变量

- 语法`ClassName(ClassName&&)`

- 示例

```cpp
class Test{
public:
    int* buf;
    Test(Test&& t) : buf(t.buf){
        t.buf = nullptr;
    }
}
```

# 类中成员函数default

### - 编译器自动生成的成员函数

- 默认构造函数：空函数，什么也不做

- 析构函数：空函数，什么也不做

- 拷贝构造函数：按bit位复制对象所占内存的内容

- 移动构造函数：同上

- 赋值运算符重载：同上

- 注意：若用户定义了上述某个成员函数，则编译器不再自动生成相应的默认实现

### - 同时使用编译器提供的成员函数

```cpp
class T{
    int data;
public:
    T() = default;
    T(int i) : data(i) {}
};
```

# 继承

### - 含义

- 在已有类(Base class)的基础上，通过继承来定义新的类(Derived class)

### - 继承方式

- private继承（缺省继承）

```cpp
class Derived : [private] Base{……};
```

- public继承

```cpp
class Derived : public Base{……};
```

### - 继承基类构造函数

```cpp
class Base{
    int data;
public:
    Base(int i) : data(i) {……}
};
class Derive : public Base{
    int data;
    using Base::Base;    //继承基类构造函数
}
```

### - 派生类中的基类成员

- 派生类中包含从基类继承来的数据成员，它们构成了“基类子对象”

- 基类中的`私有成员private`，不允许在派生类成员函数中被访问，也不允许派生类的对象访问

- 基类中的`公有成员public`
  
  - pubilc继承：成为派生类的公有成员
  
  - private继承：只能供派生类成员函数访问，不能被派生类的对象访问

- 基类中的`保护成员protected`
  
  - public继承：可以访问
  
  - private继承：变成private成员

### - 派生类中函数重写（override）

- 基类已定义的成员函数，在派生类中可以重新定义，称为“函数重写”

- 重写的函数参数，返回值应与原函数一模一样

- 重写发生时，基类中该成员函数的其他重载函数都将被屏蔽掉，不能提供给`派生类对象`使用

- 可以在派生类中通过`using 类名::成员函数名`在派生类中恢复制定的成员函数，去掉屏蔽

### - 向上映射和向下映射

- 向上映射：由派生类对象转换为基类对象
  
  - 向上映射可以由编译器自动完成，是一种隐式的自动转换
  
  - 凡是接受基类对象的地方（如函数参数），都可以使用派生类对象，编译器会自动将派生类对象转换为基类对象

```cpp
class Base{
    public:
        void print(){cout << "Base::print()" << endl;}
};
class Derive : public Base{
    public:
        void print(){cout << "Derive::print()" << endl;}
};
void fun(Base obj){
    obj.print();
}
int main(){
    Derive d;
    d.print();    //Derive::print()
    fun(d);    //Base::print()发生了向上映射
    return 0;
}
```

- 向下映射：由基类对象转换为派生类对象
  
  - 使用虚函数，让编译器自动选择合适的函数

```cpp
class Base{
    public:
        virtual void print(){cout << "Base::print()" << endl;}
};
class Derive : public Base{
    public:
        void print(){cout << "Derive::print()" << endl;}
};
void fun(Base& obj){    //obj 必须是对Base类的引用
    obj.print();
}
int main(){
    Derive d;
    d.print();    //Derive::print()
    fun(d);    //Derive::print()编译器根据d的类型选择了合适的函数
    return 0;
}
```

- - 虚析构函数

```cpp
class B{
    public:
        virtual void show(){cout << "B.show()";}
        virtual ~B(){cout << "~B()";}
};
class D : public B{
    public:
        void show(){cout << "D.show()";}
        ~D(){cout << "~D()";}
};
void test(B* ptr){                                    //若删除virtual
    ptr -> show();                //运行结果            运行结果
}                                //D.show()            D.show()
int main(){                      //~D()                ~B()
    B* ptr = new D;              //~B()
    test(ptr);
    delete ptr;
    return 0;
}
```

- 禁止重写的虚函数（final关键字）

```cpp
class A{
    public:
        virtual void fun() = 0;
};
class B : public A{
    public:
        void fun() final;    //后续子类不可重写此接口函数
};
class C ：public B{
    public:
        void fun();    //编译错误
};
```

- 纯虚函数
  
  - `fun()=0`
  
  - 包含纯虚函数的类不允许定义对象，只能为子类提供接口

# 不同类之间自动类型转换

### - 在源类中定义“目标类型转换运算符“

```cpp
class Dst{
    public:
        Dst(){cout << "Dst::Dst()" << endl;}
};
class Src{
    public:
        Src(cout << "Src::Src() << endl" << endl;)
        operator Dst() const{
            cout << "src::operator Dst() called" << endl;
            return Dst();
        }
};
```

### - 在目标类中定义“源类对象做参数的构造函数”

```cpp
class Src;    //前置类型声明
class Dst{
    public:
        Dst() {cout << "Dst::Dst()" << endl;}
        Dst(const Src& s){
            cout << "Dst::Dst(const Src&)" <<endl;
        }
};
class Src{
    public:
        Src(){cout << "Src::Src()" << endl;}
}
```

### - 禁止自动类型转换

- 分别对应以上两种方法，加关键词`explicit`

```cpp
class Dst{
    public:
        Dst(){cout << "Dst::Dst()" << endl;}
};
class Src{
    public:
        Src(cout << "Src::Src() << endl" << endl;)
        explicit
        operator Dst() const{
            cout << "src::operator Dst() called" << endl;
            return Dst();
        }
};
```

```cpp
class Src;    //前置类型声明
class Dst{
    public:
        Dst() {cout << "Dst::Dst()" << endl;}
        explicit
        Dst(const Src& s){
            cout << "Dst::Dst(const Src&)" <<endl;
        }
};
class Src{
    public:
        Src(){cout << "Src::Src()" << endl;}
}
```

- 利用`=delete`禁止自动类型转换

```cpp
class T{
    public:
        T (int){}
        T (char) = delete;
}
void fun(T t) {}
int main(){
    fun(1);
    fun('x');    //编译不通过
}
```

# 强制类型转换

### - dynamic_cast<Dst_Type>(Src_var)

- Src_var必须是引用或指针类型，Dst_Type类中含有虚函数，否则会有编译错误

- 若目标类与源类之间没有继承关系，则转换失败，返回空指针

### - static_cast<Dst_Type>(Src_var)

- 基类对象不能转换成派生类对象，但基类指针可以转换为派生类指针

- 派生类对象（指针）可以转换为基类对象（指针）

- 没有继承关系的类之间，必须有转换途径才能进行转换

# 函数模板

### - 函数模板的定义

```cpp
template<typename T>
返回类型 函数名称（函数参数）
template<typename T>
T sum(T a, T b){return a + b;}
```

### - 函数模板参数可赋默认值

```cpp
template<typename T0 = float, typename T1, typename T2 = float, 
typename T3, typename T4>
T0 fun(T1 v1, T2 v2, T3 v3, T4 v4){……}
……
fun(1,2,3);
fun('a','b','cdf');
```

# 类模板

- 基本定义

```cpp
template<typename T>class A{
    T data; 
public:
    void print(){cout << data;}
};
```

- 类模板使用流程
  
  - 类模板---实例化--->类---实例化--->对象

- 类模板参数
  
  - 类型参数：使用typename或class标记
  
  - 非类型参数：整数，枚举，指针（指向对象或函数），引用（引用对象或函数）

```cpp
template<typename T, unsigned size>
class array{
    T elems[size];
    ……
};
array<char,10> array0;    //用类模板实例定义对象
```

- - 模板参数是另一个类模板

```cpp
template<typename T,
template<typename TT0, typename TT1> class A>
struct Foo{
    A <T,T>bar;
};
```

# 模板特化

### - 函数模板特化

```cpp
template<typename T>
T sum(T a, T b){
    return a+b;
}
template<>
char* sum(char* a, char* b){
    char* p = new char[strlen(a) + strlen(b) + 1];
    strcpy(p, a);
    strcat(p, b);
    return p;
}
```

### - 类模板特化

```cpp
//通用类模板
template<class T1, class T2> class A{……};
//部分特化的模板类：第二个参数指定为int（偏特化）
template<class T1> class A <T1, int>{……};
//指定所有类型
template<> class A <int, int> {……};
```

