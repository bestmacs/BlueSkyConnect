FasdUAS 1.101.10   ��   ��    k             l     ��������  ��  ��        l      �� 	 
��   	QKCopyright 2016-2017 SolarWinds Worldwide, LLC

Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.     
 �  � C o p y r i g h t   2 0 1 6 - 2 0 1 7   S o l a r W i n d s   W o r l d w i d e ,   L L C 
 
 L i c e n s e d   u n d e r   t h e   A p a c h e   L i c e n s e ,   V e r s i o n   2 . 0   ( t h e   " L i c e n s e " ) ; 
     y o u   m a y   n o t   u s e   t h i s   f i l e   e x c e p t   i n   c o m p l i a n c e   w i t h   t h e   L i c e n s e . 
     Y o u   m a y   o b t a i n   a   c o p y   o f   t h e   L i c e n s e   a t 
 
             h t t p : / / w w w . a p a c h e . o r g / l i c e n s e s / L I C E N S E - 2 . 0 
 
     U n l e s s   r e q u i r e d   b y   a p p l i c a b l e   l a w   o r   a g r e e d   t o   i n   w r i t i n g ,   s o f t w a r e 
     d i s t r i b u t e d   u n d e r   t h e   L i c e n s e   i s   d i s t r i b u t e d   o n   a n   " A S   I S "   B A S I S , 
     W I T H O U T   W A R R A N T I E S   O R   C O N D I T I O N S   O F   A N Y   K I N D ,   e i t h e r   e x p r e s s   o r   i m p l i e d . 
     S e e   t h e   L i c e n s e   f o r   t h e   s p e c i f i c   l a n g u a g e   g o v e r n i n g   p e r m i s s i o n s   a n d 
     l i m i t a t i o n s   u n d e r   t h e   L i c e n s e .        l     ��������  ��  ��        l     ��  ��    O I This script readies and uploads a public key to the server for admin use     �   �   T h i s   s c r i p t   r e a d i e s   a n d   u p l o a d s   a   p u b l i c   k e y   t o   t h e   s e r v e r   f o r   a d m i n   u s e      l     ��������  ��  ��        l     ��  ��    + % Admin Tools require 10.11 and higher     �   J   A d m i n   T o o l s   r e q u i r e   1 0 . 1 1   a n d   h i g h e r      l     ��������  ��  ��        l     ����  r          I    �� ! "
�� .sysorpthalis        TEXT ! m      # # � $ $  s e r v e r . t x t " �� %��
�� 
in B % l    &���� & I   �� '��
�� .earsffdralis        afdr '  f    ��  ��  ��  ��     o      ���� 0 	serverloc 	serverLoc��  ��     ( ) ( l    *���� * r     + , + n     - . - 1    ��
�� 
psxp . o    ���� 0 	serverloc 	serverLoc , o      ���� 0 	serverpos 	serverPos��  ��   )  / 0 / l    1���� 1 r     2 3 2 I   �� 4��
�� .sysoexecTEXT���     TEXT 4 b     5 6 5 m     7 7 � 8 8  c a t   6 l    9���� 9 n     : ; : 1    ��
�� 
strq ; o    ���� 0 	serverpos 	serverPos��  ��  ��   3 o      ���� 0 
serveraddr 
serverAddr��  ��   0  < = < l     �� > ?��   > 7 1set serverAddr to "" -- put your server FQDN here    ? � @ @ b s e t   s e r v e r A d d r   t o   " "   - -   p u t   y o u r   s e r v e r   F Q D N   h e r e =  A B A l     ��������  ��  ��   B  C D C l    - E���� E r     - F G F I    +�� H I
�� .sysorpthalis        TEXT H m     ! J J � K K   b l u e s k y a d m i n . p u b I �� L��
�� 
in B L l  " ' M���� M I  " '�� N��
�� .earsffdralis        afdr N  f   " #��  ��  ��  ��   G o      ���� 0 adminloc adminLoc��  ��   D  O P O l  . 3 Q���� Q r   . 3 R S R n   . 1 T U T 1   / 1��
�� 
psxp U o   . /���� 0 adminloc adminLoc S o      ���� 0 adminpos adminPos��  ��   P  V W V l     �� X Y��   X _ Y or specify a different location for the file, get it from the client-files on the server    Y � Z Z �   o r   s p e c i f y   a   d i f f e r e n t   l o c a t i o n   f o r   t h e   f i l e ,   g e t   i t   f r o m   t h e   c l i e n t - f i l e s   o n   t h e   s e r v e r W  [ \ [ l     ��������  ��  ��   \  ] ^ ] l  4 M _���� _ I  4 M�� ` a
�� .sysodlogaskr        TEXT ` m   4 5 b b � c c p S e t t i n g   u p   t h i s   M a c   O R   c o p y - p a s t i n g   k e y s   f r o m   e l s e w h e r e ? a �� d e
�� 
btns d J   6 A f f  g h g m   6 9 i i � j j  C o p y - P a s t e h  k l k m   9 < m m � n n  T h i s   M a c l  o�� o m   < ? p p � q q  C a n c e l��   e �� r��
�� 
dflt r m   D G s s � t t  T h i s   M a c��  ��  ��   ^  u v u l  N U w���� w r   N U x y x l  N Q z���� z 1   N Q��
�� 
rslt��  ��   y o      ���� 0 mychoice myChoice��  ��   v  { | { l     ��������  ��  ��   |  } ~ } l  V ����  Z   V � � � � � =  V b � � � o   V Y���� 0 mychoice myChoice � K   Y a � � �� ���
�� 
bhit � m   \ _ � � � � �  T h i s   M a c��   � k   ei � �  � � � l  e e��������  ��  ��   �  � � � r   e � � � � I  e ��� � �
�� .sysodlogaskr        TEXT � l 	 e h ����� � m   e h � � � � � � P l e a s e   e n t e r   a   p a s s w o r d   t o   p r o t e c t   t h e   k e y   -   m a k e   i t   o b n o x i o u s l y   g o o d ,   i t   w i l l   b e   s t o r e d   i n   y o u r   l o g i n   K e y c h a i n :��  ��   � �� � �
�� 
appr � l 	 k n ����� � m   k n � � � � �  P a s s w o r d��  ��   � �� � �
�� 
disp � l 
 q t ����� � m   q t��
�� stic   ��  ��   � �� � �
�� 
dtxt � l 	 w z ����� � m   w z � � � � �  ��  ��   � �� � �
�� 
btns � J   { � � �  � � � m   { ~ � � � � �  C a n c e l �  ��� � m   ~ � � � � � �  O K��   � �� � �
�� 
dflt � l 
 � � ����� � m   � ����� ��  ��   � �� � �
�� 
givu � l 
 � � ����� � m   � �����'��  ��   � �� ���
�� 
htxt � m   � ���
�� boovtrue��   � o      ���� 0 
passdialog 
passDialog �  � � � r   � � � � � l  � � ����� � n   � � � � � 1   � ���
�� 
ttxt � o   � ����� 0 
passdialog 
passDialog��  ��   � o      ���� 0 my_password   �  � � � l  � ���������  ��  ��   �  � � � r   � � � � � I  � ��� ���
�� .sysoexecTEXT���     TEXT � m   � � � � � � �  w h o a m i��   � o      ���� 0 username userName �  � � � r   � � � � � I  � ��� ���
�� .sysoexecTEXT���     TEXT � m   � � � � � � �  h o s t n a m e��   � o      ���� 0 hostname hostName �  � � � l  � �� � ��   � @ :set optName to do shell script "scutil --get ComputerName"    � � � � t s e t   o p t N a m e   t o   d o   s h e l l   s c r i p t   " s c u t i l   - - g e t   C o m p u t e r N a m e " �  � � � r   � � � � � I  � ��~ ��}
�~ .sysoexecTEXT���     TEXT � m   � � � � � � �  d a t e   + % s�}   � o      �|�| 0 	epochtime 	epochTime �  � � � l  � ��{�z�y�{  �z  �y   �  � � � Q   � � � ��x � k   � � � �  � � � I  � ��w ��v
�w .sysoexecTEXT���     TEXT � m   � � � � � � � 4 r m   - f   ~ / . s s h / b l u e s k y _ a d m i n�v   �  ��u � I  � ��t ��s
�t .sysoexecTEXT���     TEXT � m   � � � � � � � < r m   - f   ~ / . s s h / b l u e s k y _ a d m i n . p u b�s  �u   � R      �r�q�p
�r .ascrerr ****      � ****�q  �p  �x   �  � � � l  � ��o�n�m�o  �n  �m   �  � � � l  � ��l � ��l   � 5 / TODO: this might screw up 10.11, needs testing    � � � � ^   T O D O :   t h i s   m i g h t   s c r e w   u p   1 0 . 1 1 ,   n e e d s   t e s t i n g �  � � � Q   �! � ��k � k   � � �  � � � r   � � � � � I  � ��j ��i
�j .sysoexecTEXT���     TEXT � b   � � � � � b   � � � � � m   � � � � � � �  g r e p   ' H o s t   � o   � ��h�h 0 
serveraddr 
serverAddr � m   � � � � � � � . '   ~ / . s s h / c o n f i g ;   e x i t   0�i   � o      �g�g 0 	hostentry 	hostEntry �  �f  Z   ��e�d =  � o   � �c�c 0 	hostentry 	hostEntry m    �   I �b�a
�b .sysoexecTEXT���     TEXT b  	 b  

 m  
 �  e c h o   ' H o s t   o  
�`�` 0 
serveraddr 
serverAddr	 m   � L 
         U s e K e y c h a i n   y e s '   > >   ~ / . s s h / c o n f i g�a  �e  �d  �f   � R      �_�^�]
�_ .ascrerr ****      � ****�^  �]  �k   �  l ""�\�[�Z�\  �[  �Z    I "M�Y�X
�Y .sysoexecTEXT���     TEXT b  "I b  "E b  "A b  "= b  "9 b  "5  b  "1!"! b  "-#$# b  ")%&% m  "%'' �(( : s s h - k e y g e n   - q   - t   e d 2 5 5 1 9   - N   '& o  %(�W�W 0 my_password  $ m  ),)) �** < '   - f   ~ / . s s h / b l u e s k y _ a d m i n   - C   "" m  -0++ �,,    u p l o a d e d @  o  14�V�V 0 	epochtime 	epochTime m  58-- �..    o  9<�U�U 0 username userName m  =@// �00  @ o  AD�T�T 0 hostname hostName m  EH11 �22  "�X   343 l NN�S�R�Q�S  �R  �Q  4 565 r  Ng787 I Nc�P9�O
�P .sysoexecTEXT���     TEXT9 b  N_:;: b  N[<=< b  NY>?> b  NU@A@ m  NQBB �CC � p u b K e y = ` o p e n s s l   s m i m e   - e n c r y p t   - a e s 2 5 6   - i n   ~ / . s s h / b l u e s k y _ a d m i n . p u b   - o u t f o r m   P E M  A l QTD�N�MD n  QTEFE 1  RT�L
�L 
strqF o  QR�K�K 0 adminpos adminPos�N  �M  ? m  UXGG �HH � ` ; c u r l   - s   - S   - m   6 0   - 1   - - r e t r y   4   - X   P O S T   - - d a t a - u r l e n c o d e   " n e w p u b = $ p u b K e y "   h t t p s : / /= o  YZ�J�J 0 
serveraddr 
serverAddr; m  [^II �JJ , / c g i - b i n / c o l l e c t o r . p h p�O  8 o      �I�I 0 uploadresult uploadResult6 K�HK l hh�G�F�E�G  �F  �E  �H   � LML = lxNON o  lo�D�D 0 mychoice myChoiceO K  owPP �CQ�B
�C 
bhitQ m  ruRR �SS  C o p y - P a s t e�B  M T�AT k  {UU VWV l {{�@�?�>�@  �?  �>  W XYX r  {�Z[Z I {��=\]
�= .sysodlogaskr        TEXT\ m  {~^^ �__ @ P l e a s e   c o p y   t h e   p u b l i c   k e y   h e r e :] �<`�;
�< 
dtxt` m  ��aa �bb  �;  [ o      �:�: 0 
dialogtemp 
dialogTempY cdc r  ��efe l ��g�9�8g n  ��hih 1  ���7
�7 
ttxti o  ���6�6 0 
dialogtemp 
dialogTemp�9  �8  f o      �5�5 0 iospub iOSpubd jkj r  ��lml I ���4no
�4 .sysodlogaskr        TEXTn m  ��pp �qq � P l e a s e   e n t e r   a   u n i q u e   d e s c r i p t i o n   f o r   t h i s   k e y .   W e   w i l l   o v e r w r i t e   k e y s   w i t h   t h e   s a m e   n a m e .o �3r�2
�3 
dtxtr m  ��ss �tt * C o p i e d   f r o m   s o m e w h e r e�2  m o      �1�1 0 dialog2temp dialog2Tempk uvu r  ��wxw l ��y�0�/y n  ��z{z 1  ���.
�. 
ttxt{ o  ���-�- 0 dialog2temp dialog2Temp�0  �/  x o      �,�, 0 optname optNamev |}| r  ��~~ I ���+��*
�+ .sysoexecTEXT���     TEXT� b  ����� b  ����� m  ���� ��� 
 e c h o  � l ����)�(� n  ����� 1  ���'
�' 
strq� o  ���&�& 0 optname optName�)  �(  � m  ���� ��� &   |   t r   [ : b l a n k : ]   ' _ '�*   o      �%�% 0 optname optName} ��� r  ����� I ���$��#
�$ .sysoexecTEXT���     TEXT� m  ���� ���  d a t e   + % s�#  � o      �"�" 0 	epochtime 	epochTime� ��� l ���!� ��!  �   �  � ��� l ������  �  �  � ��� r  ����� b  ����� b  ����� b  ����� b  ����� o  ���� 0 iospub iOSpub� m  ���� ���    p a s t e d @� o  ���� 0 	epochtime 	epochTime� m  ���� ���   � o  ���� 0 optname optName� o      �� 0 iosupl iOSupl� ��� l ������  �  �  � ��� r  ���� I ����
� .sysoexecTEXT���     TEXT� b  �
��� b  ���� b  ���� b  � ��� b  ����� b  ����� m  ���� ���  p u b K e y = ` e c h o   '� o  ���� 0 iosupl iOSupl� m  ���� ��� ` '   |   o p e n s s l   s m i m e   - e n c r y p t   - a e s 2 5 6   - o u t f o r m   P E M  � l ������ n  ����� 1  ���
� 
strq� o  ���� 0 adminpos adminPos�  �  � m   �� ��� � ` ; c u r l   - s   - S   - m   6 0   - 1   - - r e t r y   4   - X   P O S T   - - d a t a - u r l e n c o d e   " n e w p u b = $ p u b K e y "   h t t p s : / /� o  �� 0 
serveraddr 
serverAddr� m  	�� ��� , / c g i - b i n / c o l l e c t o r . p h p�  � o      �� 0 uploadresult uploadResult� ��� l �
�	��
  �	  �  �  �A   � L  �� m  ��  ��  ��   ~ ��� l     ����  �  �  � ��� l g���� Z  g����� E  !��� o  � �  0 uploadresult uploadResult� m   �� ���  I n s t a l l e d� I $5����
�� .sysodlogaskr        TEXT� m  $'�� ���   Y o u   a r e   a l l   s e t !� ����
�� 
btns� m  (+�� ���  W o o h o o !� �����
�� 
dflt� m  ./���� ��  � ��� E  8?��� o  8;���� 0 uploadresult uploadResult� m  ;>�� ���  U p g r a d e� ���� I BS����
�� .sysodlogaskr        TEXT� m  BE�� ��� d P l e a s e   r e - d o w n l o a d   A d m i n   T o o l s   a n d   t r y   t h i s   a g a i n .� ����
�� 
btns� m  FI�� ���  O k a y� �����
�� 
dflt� m  LM���� ��  ��  � I Vg����
�� .sysodlogaskr        TEXT� m  VY�� ��� N S o m e t h i n g   w e n t   w r o n g .   P l e a s e   t r y   a g a i n .� ����
�� 
btns� m  Z]�� ���  W e a k� �����
�� 
dflt� m  `a���� ��  �  �  �       ������  � ��
�� .aevtoappnull  �   � ****� �����������
�� .aevtoappnull  �   � ****� k    g��  ��  (��  /��  C��  O��  ]    u  } �����  ��  ��  �  � ` #������������ 7������ J���� b�� i m p�� s���������� � ��� ������� � � ��������������� ��� ��� ��� � ����� � ���')+-/1BGI��R^a����ps�����������������������
�� 
in B
�� .earsffdralis        afdr
�� .sysorpthalis        TEXT�� 0 	serverloc 	serverLoc
�� 
psxp�� 0 	serverpos 	serverPos
�� 
strq
�� .sysoexecTEXT���     TEXT�� 0 
serveraddr 
serverAddr�� 0 adminloc adminLoc�� 0 adminpos adminPos
�� 
btns
�� 
dflt�� 
�� .sysodlogaskr        TEXT
�� 
rslt�� 0 mychoice myChoice
�� 
bhit
�� 
appr
�� 
disp
�� stic   
�� 
dtxt
�� 
givu��'
�� 
htxt�� �� 0 
passdialog 
passDialog
�� 
ttxt�� 0 my_password  �� 0 username userName�� 0 hostname hostName�� 0 	epochtime 	epochTime��  ��  �� 0 	hostentry 	hostEntry�� 0 uploadresult uploadResult�� 0 
dialogtemp 
dialogTemp�� 0 iospub iOSpub�� 0 dialog2temp dialog2Temp�� 0 optname optName�� 0 iosupl iOSupl��h��)j l E�O��,E�O���,%j 	E�O��)j l E�O��,E�O��a a a mva a a  O_ E` O_ a a l 	a a a a a a  a !�a "a #lva la $a %a &ea ' E` (O_ (a ),E` *Oa +j 	E` ,Oa -j 	E` .Oa /j 	E` 0O a 1j 	Oa 2j 	W X 3 4hO 2a 5�%a 6%j 	E` 7O_ 7a 8  a 9�%a :%j 	Y hW X 3 4hOa ;_ *%a <%a =%_ 0%a >%_ ,%a ?%_ .%a @%j 	Oa A��,%a B%�%a C%j 	E` DOPY �_ a a El  �a Fa  a Gl E` HO_ Ha ),E` IOa Ja  a Kl E` LO_ La ),E` MOa N_ M�,%a O%j 	E` MOa Pj 	E` 0O_ Ia Q%_ 0%a R%_ M%E` SOa T_ S%a U%��,%a V%�%a W%j 	E` DOPY jO_ Da X a Y�a Za ka  Y 1_ Da [ a \�a ]a ka  Y a ^�a _a ka   ascr  ��ޭ