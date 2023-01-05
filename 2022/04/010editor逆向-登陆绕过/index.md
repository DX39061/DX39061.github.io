# 010Editor逆向-登陆绕过


## 010editor登陆绕过

### patch__1.0

- 起因是30天试用期到了，又想白嫖，于是试试逆向搞它，确实不难

- 拖进ida静态分析就行

- string窗口搜索`license`，找到关键语句
  
  ![010_patch.png](/upload/2022/04/010_patch-0cc75362d9b54a239a3f0751eb4f9357.png)

- `Password accepted. This license entitles you to:\n\n - Free Upgrades\n - Free Support\n - Free Repository Updates\n\nuntil `显然是验证通过后的提示语句，跟进去

- 交叉引用定位`loc_72F4D8`函数

```nasm
.text:000000000072F4D8 loc_72F4D8:                             ; CODE XREF: sub_72EA00+6AE↑j
.text:000000000072F4D8                 mov     rdi, [r15]
.text:000000000072F4DB ;   try {
.text:000000000072F4DB                 call    _ZN9RRegister14GetExpiryQDateEv ; RRegister::GetExpiryQDate(void)
.text:000000000072F4E0                 lea     rdi, unk_8ACB72 ; this
.text:000000000072F4E7                 mov     esi, 0Ch        ; char *
.text:000000000072F4EC                 mov     [rsp+228h+var_68], rax
.text:000000000072F4F4                 call    __ZN7QString16fromAscii_helperEPKci ; QString::fromAscii_helper(char const*,int)
.text:000000000072F4F4 ;   } // starts at 72F4DB
.text:000000000072F4F9                 mov     [rsp+228h+var_48], rax
.text:000000000072F501                 lea     rbp, [rsp+228h+var_48]
.text:000000000072F509                 lea     rax, [rsp+228h+var_128]
.text:000000000072F511                 lea     rsi, [rsp+228h+var_68] ; QString *
.text:000000000072F519                 mov     rdx, rbp
.text:000000000072F51C                 mov     rdi, rax        ; this
.text:000000000072F51F                 mov     r13, rax
.text:000000000072F522                 mov     [rsp+228h+var_220], rax
.text:000000000072F527 ;   try {
.text:000000000072F527                 call    __ZNK5QDate8toStringERK7QString ; QDate::toString(QString const&)
.text:000000000072F527 ;   } // starts at 72F527
.text:000000000072F52C                 lea     r14, [rsp+228h+var_118]
.text:000000000072F534                 lea     rsi, aPasswordAccept_0 ; "Password accepted. This license entitle"...
.text:000000000072F53B                 mov     edx, 78h ; 'x'  ; int
.text:000000000072F540                 mov     rdi, r14        ; this
.text:000000000072F543 ;   try {
.text:000000000072F543                 call    __ZN7QString15fromUtf8_helperEPKci ; QString::fromUtf8_helper(char const*,int)
```

- 再往上找发现`loc_72F0A8`函数

```nasm
.text:000000000072F0A8 loc_72F0A8:                             ; CODE XREF: sub_72EA00+5FA↑j
.text:000000000072F0A8                                         ; sub_72EA00+608↑j
.text:000000000072F0A8                 cmp     ebp, 0DBh
.text:000000000072F0AE                 jz      loc_72F4D8;上个函数入口
.text:000000000072F0B4                 cmp     ebp, 0EDh
.text:000000000072F0BA                 jz      loc_72F1C8
.text:000000000072F0C0                 cmp     ebp, 20Ch
.text:000000000072F0C6                 jz      loc_72F1C8
.text:000000000072F0CC                 cmp     r13d, 93h
.text:000000000072F0D3                 jz      short loc_72F148
.text:000000000072F0D5                 lea     rdi, aInvalidNameOrP ; "Invalid name or password. Please enter "...
.text:000000000072F0DC                 mov     esi, 90h        ; char *
.text:000000000072F0E1                 call    __ZN7QString16fromAscii_helperEPKci ; QString::fromAscii_helper(char const*,int)
.text:000000000072F0E1 ;   } // starts at 72F09D
.text:000000000072F0E6                 lea     rbp, [rsp+228h+var_48]
.text:000000000072F0EE                 mov     [rsp+228h+var_48], rax
.text:000000000072F0F6                 mov     rdi, rbp
.text:000000000072F0F9 ;   try {
.text:000000000072F0F9                 call    _Z10R_ShowInfoRK7QString ; R_ShowInfo(QString const&)
.text:000000000072F0F9 ;   } // starts at 72F0F9
.text:000000000072F0FE                 jmp     loc_72F04B
```

- 跳转语句`jz loc_72F4D8`，尝试性把jz改成jnz，apply一下

- 重新进入010，弹出register窗口，随便输入用户名和密码，点击`check license`

![010_2.png](/upload/2022/04/010_2-4b26d1c6c078458bace506d6264734f6.png)

- 弹出成功窗口
  ![010_3.png](/upload/2022/04/010_3-446c98d98f924921aa186fb95ef4b8d9.png)

- 点击ok成功进入应用，成功！

### patch__2.0

- 上次搞完之后能用是能用，但是每次都要点击上面两张图的`Check License`和`OK`，十分不方便，于是尝试使2个界面不再弹出

- 仔细看main函数，还是挺清晰的

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  volatile signed __int32 *v3; // rsi
  int v4; // edx
  int v5; // ecx
  int v6; // er8
  int v7; // er9
  TForm010Ed *v8; // rdi
  __int64 (__fastcall ***v9)(_QWORD); // rax
  QMetaObject *v10; // rax
  const char *v11; // rax
  int v12; // edx
  volatile signed __int32 *v13; // rax
  __int64 v14; // rdx
  char *v15; // rsi
  QApplication *v16; // r14
  const QString *v17; // rdx
  __int64 v18; // r14
  TForm010Ed *v19; // rdi
  unsigned int v20; // er15
  int v21; // eax
  QObject *v22; // r14
  const char *v23; // rdx
  QApplication *v24; // rdi
  unsigned int v25; // er13
  QTimer *v26; // rdx
  __int64 v27; // r14
  volatile signed __int32 **v28; // r13
  volatile signed __int32 *v29; // rax
  volatile signed __int32 **v30; // r8
  volatile signed __int32 **i; // rdx
  int v33; // edx
  QDesktopWidget *v34; // rax
  __int64 v35; // rsi
  const char *v36; // rcx
  QWidget *v37; // [rsp+0h] [rbp-178h]
  int v38; // [rsp+0h] [rbp-178h]
  QWidget *v39; // [rsp+0h] [rbp-178h]
  QWidget *v40; // [rsp+0h] [rbp-178h]
  QWidget *v41; // [rsp+0h] [rbp-178h]
  char v42; // [rsp+8h] [rbp-170h]
  int v43; // [rsp+8h] [rbp-170h]
  int v44; // [rsp+10h] [rbp-168h]
  int v45; // [rsp+10h] [rbp-168h]
  void *v46; // [rsp+18h] [rbp-160h] BYREF
  int v47[2]; // [rsp+20h] [rbp-158h] BYREF
  QTimer *v48; // [rsp+28h] [rbp-150h]
  QTimer *v49[2]; // [rsp+30h] [rbp-148h] BYREF
  QDateTime *v50; // [rsp+40h] [rbp-138h] BYREF
  char v51; // [rsp+48h] [rbp-130h]
  int v52; // [rsp+50h] [rbp-128h] BYREF
  char v53; // [rsp+58h] [rbp-120h]
  __int64 v54; // [rsp+60h] [rbp-118h] BYREF
  int v55; // [rsp+68h] [rbp-110h]
  int v56; // [rsp+70h] [rbp-108h] BYREF
  char v57; // [rsp+78h] [rbp-100h]
  int v58; // [rsp+80h] [rbp-F8h] BYREF
  char v59; // [rsp+88h] [rbp-F0h]
  int v60; // [rsp+90h] [rbp-E8h] BYREF
  char v61; // [rsp+98h] [rbp-E0h]
  int v62[2]; // [rsp+A0h] [rbp-D8h] BYREF
  char v63; // [rsp+A8h] [rbp-D0h]
  char v64[32]; // [rsp+B0h] [rbp-C8h] BYREF
  char v65[104]; // [rsp+D0h] [rbp-A8h] BYREF
  unsigned __int64 v66; // [rsp+138h] [rbp-40h]

  v66 = __readfsqword(0x28u);
  qInstallMessageHandler(&R_MessageOutput, a2, a3);
  sub_5680C0();
  nullsub_31();
  RProgress::CreateProgress((RProgress *)&R_MessageOutput);
  QCoreApplication::setAttribute(20LL, 1LL);
  QCoreApplication::setAttribute(13LL, 1LL);
  v3 = (volatile signed __int32 *)&v46 + 1;
  sub_5943F0((QObject *)v65, v37, v42, v44, (int)v46, (int)&QArrayData::shared_null, (char)v48);
  dword_10B8F10 = (RApplication *)v65;
  sub_595D00((unsigned int)v65, (unsigned int)&v46 + 4, v4, v5, v6, v7, v38, v43, v45, (char)v46);
  v8 = (TForm010Ed *)v49;
  QCoreApplication::arguments((QCoreApplication *)v49);
  if ( !(unsigned int)TForm010Ed::CheckRunOnlyOnce((TForm010Ed *)v49)
    || (v8 = dword_10B8F10, !(unsigned int)sub_594C60(dword_10B8F10)) )
  {
    TForm010Ed::CheckDebugFlags(v8);
    v9 = (__int64 (__fastcall ***)(_QWORD))QApplication::style(v8);
    v10 = (QMetaObject *)(**v9)(v9);
    v11 = (const char *)QMetaObject::className(v10);
    v12 = -1;
    if ( v11 )
      v12 = strlen(v11);
    QString::fromUtf8_helper((QString *)v62, v11, v12);
    v13 = *(volatile signed __int32 **)v47;
    v14 = *(_QWORD *)v62;
    *(_QWORD *)v62 = *(_QWORD *)v47;
    *(_QWORD *)v47 = v14;
    if ( !**(_DWORD **)v62 || **(_DWORD **)v62 != -1 && !_InterlockedDecrement(v13) )
      QArrayData::deallocate(*(_QWORD *)v62, 2LL, 8LL);
    v15 = "QCleanlooksStyle";
    if ( (unsigned __int8)QString::operator==(v47, "QCleanlooksStyle")
      || (v15 = "QCDEStyle", (unsigned __int8)QString::operator==(v47, "QCDEStyle"))
      || (v15 = "QPlastiqueStyle", (unsigned __int8)QString::operator==(v47, "QPlastiqueStyle"))
      || (v15 = "QMotifStyle", (unsigned __int8)QString::operator==(v47, "QMotifStyle"))
      || (v15 = "QWindowsStyle", (unsigned __int8)QString::operator==(v47, "QWindowsStyle"))
      || (v15 = "QGtkStyle", (unsigned __int8)QString::operator==(v47, "QGtkStyle"))
      || (v15 = "QFusionStyle", (unsigned __int8)QString::operator==(v47, "QFusionStyle")) )
    {
      v16 = (QApplication *)operator new(0x10uLL);
      sub_56DC50(v16);
      QApplication::setStyle(v16, (QStyle *)v15);
    }
    R_InitializeCustomCodecs();
    QGuiApplication::setLayoutDirection(0LL);
    RStandardPaths::GetProgDir((RStandardPaths *)&v54, 1);
    v39 = (QWidget *)&v54;
    operator+((QString *)&v56);
    RStandardPaths::GetProgDir((RStandardPaths *)&v50, 1);
    operator+((QString *)&v52);
    RHelp::Initialize((RHelp *)&v52, (const QString *)&v56, v17);
    QString::~QString((QString *const)&v52);
    QString::~QString((QString *const)&v50);
    QString::~QString((QString *const)&v56);
    QString::~QString((QString *const)&v54);
    if ( (int)sub_45E320() < 0 )
      goto LABEL_42;
    v18 = operator new(0x50uLL);
    sub_52F000(v18);
    unk_10B8F38 = v18;
    sub_52FD20(v18);
    if ( !*((_DWORD *)dword_10B8F10 + 8) )
      RRegister::DecreaseNumUsesLeft(unk_10B8F38);
    RRegister::CheckPortableInstallLicenseFromLocal(unk_10B8F38);
    v19 = (TForm010Ed *)unk_10B8F38;
    v20 = RRegister::CheckStatus(unk_10B8F38, 13, 18887);
    if ( *((_DWORD *)dword_10B8F10 + 8) && v20 != 219 )
    {
      v19 = (TForm010Ed *)unk_10B8F38;
      RRegister::DecreaseNumUsesLeft(unk_10B8F38);
    }
    v21 = TForm010Ed::CheckNoUserInterface(v19);
    unk_10B8FA5 = v21 != 0;
    if ( !v21 && (!(unsigned int)sub_5A8A90() || v20 != 219) )
    {
      *(_QWORD *)v62 = QString::fromAscii_helper((QString *)":/Icons/resources/Splash.png", (const char *)0x1C, v33);
      QPixmap::QPixmap(v64, v62, 0LL, 0LL);
      QString::~QString((QString *const)v62);
      v34 = (QDesktopWidget *)QApplication::desktop((QApplication *)v62);
      v35 = QDesktopWidget::screen(v34, -1);
      v39 = (QWidget *)operator new(0x40uLL);
      sub_59A250(v39, v35, v64, 0x40000LL, v20);
      qword_10B8EF0 = v39;
      QWidget::show(v39);
      QSplashScreen::repaint(qword_10B8EF0);
      QCoreApplication::processEvents(0LL);
      QTimer::singleShot((QTimer *)0x9C4, (int)dword_10B8F10, (const QObject *)"1on_CloseSplash()", v36);
      QPixmap::~QPixmap((QPixmap *)v64);
    }
    v22 = (QObject *)operator new(0x1288uLL);
    sub_5D92B0(
      v22,
      (__int64)v39,
      (int)&v56,
      (int)v62,
      v46,
      v47[0],
      v48,
      v49[0],
      v49[1],
      v50,
      v51,
      v52,
      v53,
      v54,
      v55,
      v56,
      v57,
      v58,
      v59,
      v60,
      v61,
      v62[0],
      v63);
    qword_10B8EF8 = v22;
    QWidget::setUpdatesEnabled(v22, 0);
    sub_584E10(v64, unk_10B8F00);
    QApplication::setPalette((QApplication *)v64, 0LL, v23);
    if ( (unsigned int)sub_5B5A80(qword_10B8EF8) == -1 )
      goto LABEL_46;
    if ( v20 == 375
      || v20 == 47
      || v20 == 237
      || v20 == 275
      || v20 == 524 && (unsigned int)RRegister::CheckForNotice(unk_10B8F38) )
    {
      QString::fromUtf8_helper((QString *)&v58, ":/Icons/resources/010_icon_32x32.png", 36);
      QIcon::QIcon((QIcon *)&v60, (const QString *)&v58);
      QApplication::setWindowIcon((QApplication *)&v60, (const QIcon *)&v58);
      QIcon::~QIcon((QIcon *)&v60);
      QString::~QString((QString *const)&v58);
      if ( !qword_10B9690 )
      {
        v41 = (QWidget *)operator new(0x1C0uLL);
        sub_72FF40(v41);
        qword_10B9690 = v41;
      }
      sub_72DF80(qword_10B9690);
      RApplication::on_CloseSplash((RApplication *)v65);
      if ( !(*(unsigned int (__fastcall **)(QObject *, __int64))(*(_QWORD *)qword_10B9690 + 424LL))(qword_10B9690, 1LL)
        && *((_DWORD *)qword_10B9690 + 102) )
      {
        v25 = -1;
        goto LABEL_47;
      }
      if ( qword_10B9690 )
        (*(void (__fastcall **)(QObject *))(*(_QWORD *)qword_10B9690 + 32LL))(qword_10B9690);
      v40 = (QWidget *)operator new(0x1C0uLL);
      sub_72FF40(v40);
      qword_10B9690 = v40;
    }
    if ( unk_10B8FA5 )
    {
      sub_5D85A0(qword_10B8EF8, (__int64)v40);
    }
    else if ( *((_DWORD *)qword_10B8EF8 + 1049) )
    {
      QWidget::showNormal(qword_10B8EF8);
      QWidget::showMaximized(qword_10B8EF8);
    }
    else
    {
      QWidget::show(qword_10B8EF8);
    }
    QWidget::setUpdatesEnabled(qword_10B8EF8, 1);
    sub_5D50C0(qword_10B8EF8);
    v24 = qword_10B8EF8;
    TForm010Ed::RunCommandLineParams(qword_10B8EF8);
    if ( unk_10B8FAA || unk_10B8FA5 && (v24 = qword_10B8EF8, !(unsigned int)sub_5B2BE0(qword_10B8EF8)) )
LABEL_46:
      v25 = unk_10B8F98;
    else
      v25 = QApplication::exec(v24);
LABEL_47:
    QPalette::~QPalette((QPalette *)v64);
    goto LABEL_43;
  }
  RApplication::SendBringToFrontMessage(dword_10B8F10);
  v26 = v49[0];
  v27 = 1LL;
  if ( *((_DWORD *)v49[0] + 3) - *((_DWORD *)v49[0] + 2) > 1 )
  {
    do
    {
      if ( *(_DWORD *)v26 > 1u )
      {
        v28 = (volatile signed __int32 **)((char *)v49[0] + 8 * *((int *)v49[0] + 2) + 16);
        v29 = (volatile signed __int32 *)QListData::detach((QListData *)v49, *((_DWORD *)v49[0] + 1));
        v3 = (volatile signed __int32 *)*((int *)v49[0] + 3);
        v30 = (volatile signed __int32 **)((char *)v49[0] + 8 * (_QWORD)v3 + 16);
        for ( i = (volatile signed __int32 **)((char *)v49[0] + 8 * *((int *)v49[0] + 2) + 16); v30 != i; ++v28 )
        {
          if ( i )
          {
            v3 = *v28;
            *i = *v28;
            if ( (unsigned int)(*v3 + 1) > 1 )
              _InterlockedAdd(v3, 1u);
          }
          ++i;
        }
        if ( !*v29 || *v29 != -1 && !_InterlockedSub(v29, 1u) )
          QList<QString>::dealloc(v29);
        v26 = v49[0];
      }
      TForm010Ed::SendLoadFileMessage(
        (QTimer *)((char *)v26 + 8 * v27 + 8 * *((int *)v26 + 2) + 16),
        (const QString *)v3);
      v26 = v49[0];
      ++v27;
    }
    while ( (int)v27 < *((_DWORD *)v49[0] + 3) - *((_DWORD *)v49[0] + 2) );
  }
LABEL_42:
  v25 = 0;
LABEL_43:
  QList<QLabel *>::~QList(v49);
  sub_45E4E0((QApplication *)v65);
  QString::~QString((QString *const)v47);
  return v25;
}
```

- 发现函数`RRegister::CheckStatus`，猜测应该是检查是否在30天试用期内，具体原理不明，查看汇编

```nasm
.text:000000000045CEB3 loc_45CEB3:                             ; CODE XREF: main+6CE↓j
.text:000000000045CEB3                 lea     rax, unk_10B8F38
.text:000000000045CEBA                 mov     rdi, [rax]
.text:000000000045CEBD                 call    _ZN9RRegister36CheckPortableInstallLicenseFromLocalEv ; RRegister::CheckPortableInstallLicenseFromLocal(void)
.text:000000000045CEC2                 lea     rax, unk_10B8F38
.text:000000000045CEC9                 mov     edx, 49C7h
.text:000000000045CECE                 mov     esi, 0Dh
.text:000000000045CED3                 mov     rdi, [rax]
.text:000000000045CED6                 call    _ZN9RRegister11CheckStatusEii ; RRegister::CheckStatus(int,int)
.text:000000000045CEDB                 cmp     eax, 0DBh
.text:000000000045CEE0                 mov     r15d, eax
.text:000000000045CEE3                 mov     rax, [r13+0]
.text:000000000045CEE7                 setnz   r14b
.text:000000000045CEEB                 cmp     dword ptr [rax+20h], 0
.text:000000000045CEEF                 jz      short loc_45CF05
.text:000000000045CEF1                 test    r14b, r14b
.text:000000000045CEF4                 jz      short loc_45CF05
.text:000000000045CEF6                 lea     rax, unk_10B8F38
.text:000000000045CEFD                 mov     rdi, [rax]
.text:000000000045CF00                 call    _ZN9RRegister19DecreaseNumUsesLeftEv ; RRegister::DecreaseNumUsesLeft(void)
```

- 尝试把`call RRegister::CheckStatus`整个patch掉，使其不进行检查直接进入应用

- apply一下，重新运行程序，成功！

