# Immortal Android Applications
***Construct a unprivileged Android application that can never be killed by Linux out-of-memory(oom) killer.***

MIT License

Copyright (c) 2019 Zephyr Yao

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Background
### oom-killer
oom-killer is a Linux kernel feature that sacrifices certain processes to free up system memory [1].
When the system memory is running low, oom-killer tends to kill a process of lower importance. 
This priority order is based on the process' oom_score, which can be read from `/proc/<PID>/oom_score`. 
With appropriate privilege, a user can set the score by writing to `/proc/<PID>/oom_adj`.

A higher score indicates the process is less important, and thus becomes a better candidate for the oom-killer to eliminate. 
There exists a special const, `OOM_DISABLE = -17`. 
Setting a process' oom_score to `-17` immunizes the process against the oom killer [1]. 
Even the system runs out of memory, which will lead to a kernel panic, the immunized process will not be killed.

### Android Low Memory Killer (LMP) - a supplement to oom-killer
Nowadays computers come with an abundant amount of RAM, but smartphones usually have little. 
Another important difference is that the Linux kernel oom-killer does not take application priorities into consideration [3], such as application visibility, whether it is a long-run service, etc. 
Android LMK supplements the oom-killer by dynamically adjusting the applications' oom_scores. 

Kim et al. draw a very nice diagram (see below) explaining the relationship between LMP and oom-killer [4].

![Kim et al](https://media.springernature.com/lw785/springer-static/image/chp%3A10.1007%2F978-94-017-9618-7_14/MediaObjects/328731_1_En_14_Fig1_HTML.gif)

### Android permission on oom_score settings
As mentioned in [5], Android system does not allow any application to lower its oom_score, which means, any application can make itself less-important ("a potential suicide"[5]), but not more important.
Otherwise the write syscall will return a permission error, `EACCESS`.

### Similar work
The application doesn't have the permission to adjust its oom_score, but the Android framework does.
[6] exploits this property to gain lower oom_score by sending empty notifications (`Toasts`).
By doing this, even the application is in the background, the Android framework thinks the application is important and assigns lower oom_score for a few seconds.
Other attempts to fool oom-killer require root access, or access to shell [7][8].

## A magical workaround
The Linux kernel below is extracted from `oom_badness()`, which is a "heuristic function to determine which candidate task to kill" [[linux/mm/oom_kill.c](https://github.com/torvalds/linux/blob/cefc7ef3c87d02fc9307835868ff721ea12cc597/mm/oom_kill.c)].
```c
	/*
	 * Do not even consider tasks which are explicitly marked oom
	 * unkillable or have been already oom reaped or the are in
	 * the middle of vfork
	 */
	adj = (long)p->signal->oom_score_adj;
	if (adj == OOM_SCORE_ADJ_MIN ||
			test_bit(MMF_OOM_SKIP, &p->mm->flags) ||
			in_vfork(p)) {
		task_unlock(p);
		return 0;
	}
```

Among the special cases that cause the oom_killer to skip the current process, `in_vfork(p)` is something we can manipulate.
Unlike `fork()`, the child process created by `vfork()` shares the same address space as the parent process.
The oom_killer skips a process in the middle of `vfork()` avoids potential undefined behavior of the user processes.
Apparently, this merciful special case is not designed against potential malicious apps.
A malicious app wants to avoid being killed by oom-killer can repeatedly set itself in the middle of `vfork()`.

A simple PoC can be,
```c
void main(void) {
     pid_t pid;
     while (true) {
     pid = vfork();
     if (pid == 0) 
          return 0;
     }
}
```

Of course executing the `vfork()` will slow down the application and even the system, but leaving it running on a worker thread yields immortality - worth it.

## Comments
This work shows the feasibility for a unprivileged application to survive against the oom-killer. This method is not intended to be used in any real application.

Android Developers should exercise their best practices (see [2]) to avoid out-of-memory problems. 

## References

[1] OOM_Killer - linux-mm.org Wiki. https://linux-mm.org/OOM_Killer

[2] Android Out of Memory Error: Causes, Solution and Best practices. http://blogs.innovationm.com/android-out-of-memory-error-causes-solution-and-best-practices

[3] Joongjin Kook, Sukil Hong, Wooseung Lee, Eunkyeung Jae, and JungYeop Kim. 2011. Optimization of out of memory killer for embedded Linux environments. In Proceedings of the 2011 ACM Symposium on Applied Computing (SAC '11). ACM, New York, NY, USA, 633-634. DOI: https://doi.org/10.1145/1982185.1982324

[4] Jang Hyun Kim, Junghwan Sung, Sang Yun Hwang, and Hyo-Joong Suh. 2015. A novel android memory management policy focused on periodic habits of a user. In Ubiquitous Computing Application and Wireless Sensor, Springer, Dordrecht, 143-149.

[5] Android - Foolproof low memory killer. http://debuggingisfun.blogspot.com/2014/03/android-foolproof-low-memory-killer.html

[6] Android - Exploit to stay Foreground without foreground service. http://debuggingisfun.blogspot.com/2014/10/android-hack-to-stay-foreground-without.html

[7] ram - How to lower OOM value of an app permanently. https://android.stackexchange.com/questions/23469/how-to-lower-oom-value-of-an-app-permanently

[8] [FIX] Bulletproof Background Apps. https://forum.xda-developers.com/showthread.php?t=1012330
