
****
NAME
****


parcat - cat files or fifos in parallel


********
SYNOPSIS
********


\ **parcat**\  [--rm] [-#] file(s) [-#] file(s)


***********
DESCRIPTION
***********


GNU \ **parcat**\  reads files or fifos in parallel. It writes full lines so there will be no problem with mixed-half-lines which you risk if you use:


.. code-block:: bash

    (cat file1 & cat file2 &) | ...


It is faster than doing:


.. code-block:: bash

    parallel -j0 --lb cat ::: file*


Arguments can be given on the command line or passed in on stdin (standard input).


*******
OPTIONS
*******



- \-\ **#**\ 
 
 Arguments following this will be sent to the file descriptor \ **#**\ . E.g.
 
 
 .. code-block:: bash
 
    parcat -1 stdout1 stdout2 -2 stderr1 stderr2
 
 
 will send \ *stdout1*\  and \ *stdout2*\  to stdout (standard output = file descriptor 1), and send \ *stderr1*\  and \ *stderr2*\  to stderr (standard error = file descriptor 2).
 


- \--rm
 
 Remove files after opening. As soon as the files are opened, unlink the files.
 



********
EXAMPLES
********


Simple line buffered output
===========================


\ **traceroute**\  will often print half a line. If run in parallel, two instances may half-lines of their output. This can be avoided by saving the output to a fifo and then using \ **parcat**\  to read the two fifos in parallel:


.. code-block:: bash

   mkfifo freenetproject.org.fifo tange.dk.fifo
   traceroute freenetproject.org > freenetproject.org.fifo &
   traceroute tange.dk > tange.dk.fifo &
   parcat --rm *fifo




**************
REPORTING BUGS
**************


GNU \ **parcat**\  is part of GNU \ **parallel**\ . Report bugs to <bug-parallel@gnu.org>.


******
AUTHOR
******


Copyright (C) 2016-2025 Ole Tange, http://ole.tange.dk and Free Software Foundation, Inc.


*******
LICENSE
*******


This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 3 of the License, or at your option any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program.  If not, see <http://www.gnu.org/licenses/>.

Documentation license I
=======================


Permission is granted to copy, distribute and/or modify this documentation under the terms of the GNU Free Documentation License, Version 1.3 or any later version published by the Free Software Foundation; with no Invariant Sections, with no Front-Cover Texts, and with no Back-Cover Texts.  A copy of the license is included in the file LICENSES/GFDL-1.3-or-later.txt.


Documentation license II
========================


You are free:


- \ **to Share**\ 
 
 to copy, distribute and transmit the work
 


- \ **to Remix**\ 
 
 to adapt the work
 


Under the following conditions:


- \ **Attribution**\ 
 
 You must attribute the work in the manner specified by the author or licensor (but not in any way that suggests that they endorse you or your use of the work).
 


- \ **Share Alike**\ 
 
 If you alter, transform, or build upon this work, you may distribute the resulting work only under the same, similar or a compatible license.
 


With the understanding that:


- \ **Waiver**\ 
 
 Any of the above conditions can be waived if you get permission from the copyright holder.
 


- \ **Public Domain**\ 
 
 Where the work or any of its elements is in the public domain under applicable law, that status is in no way affected by the license.
 


- \ **Other Rights**\ 
 
 In no way are any of the following rights affected by the license:
 
 
 - 
  
  Your fair dealing or fair use rights, or other applicable copyright exceptions and limitations;
  
 
 
 - 
  
  The author's moral rights;
  
 
 
 - 
  
  Rights other persons may have either in the work itself or in how the work is used, such as publicity or privacy rights.
  
 
 


- \ **Notice**\ 
 
 For any reuse or distribution, you must make clear to others the license terms of this work.
 


A copy of the full license is included in the file as LICENCES/CC-BY-SA-4.0.txt



************
DEPENDENCIES
************


GNU \ **parcat**\  uses Perl.


********
SEE ALSO
********


\ **cat**\ (1), \ **parallel**\ (1)

