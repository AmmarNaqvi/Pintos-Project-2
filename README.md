# Pintos-Project-2
http://www.scs.stanford.edu/15au-cs140/pintos/pintos_2.html


<P>

Now that you've worked with Pintos and are becoming familiar with its
infrastructure and thread package, it's time to start working on the
parts of the system that allow running user programs.
The base code already supports loading and
running user programs, but no I/O or interactivity
is possible.  In this project, you will enable programs to interact with
the OS via system calls.
</P>
<P>

You will be working out of the <Q><TT>userprog</TT></Q> directory for this
assignment, but you will also be interacting with almost every
other part of Pintos.  We will describe the
relevant parts below.
</P>
<P>

You can build project 2 on top of your project 1 submission or you can
start fresh.  No code from project 1 is required for this
assignment.  The &quot;alarm clock&quot; functionality may be useful in
projects 3 and 4, but it is not strictly required.
</P>
<P>

You might find it useful to go back and reread how to run the tests
(see section <A HREF="pintos_1.html#SEC8">1.2.1 Testing</A>).
</P>
<P>
