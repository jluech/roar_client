from copy import deepcopy
import os

# FP directories
fp_dir = "C:/Users/jluec/Desktop/fingerprints"
normal_fp_dir = os.path.join(fp_dir, "normal")
infected_c1_fp_dir = os.path.join(fp_dir, "infected-c1")
fp_dirs = [normal_fp_dir, infected_c1_fp_dir]

# headers based on FP script fingerprinter.sh
CPU_HEADERS = "cpu_us,cpu_sy,cpu_ni,cpu_id,cpu_wa,cpu_hi,cpu_si"  # 2,4,6,8,10,12,14 of [2-us,sy,ni,id,wa,hi,14-si,st]
TASKS_HEADERS = "tasks_total,tasks_running,tasks_sleeping,tasks_stopped,tasks_zombie"  # 2,4,6,8,10 = all
MEM_HEADERS = "mem_free,mem_used,mem_cache"  # 6,8,10 of [total,6-free,used,10-buff/cache]
SWAP_HEADERS = "swap_avail"  # 9 of [total,free,used,9-availMem]
NETWORK_HEADERS = "net_lo_rx,net_lo_tx,net_eth_rx,net_eth_tx"  # RX packets and TX packets for loopback and ethernet
CSV_HEADERS = "time,timestamp,seconds,connectivity,{},{},{},{},{},cpu_temp,alarmtimer:alarmtimer_fired,alarmtimer:alarmtimer_start,block:block_bio_backmerge,block:block_bio_remap,block:block_dirty_buffer,block:block_getrq,block:block_touch_buffer,block:block_unplug,cachefiles:cachefiles_create,cachefiles:cachefiles_lookup,cachefiles:cachefiles_mark_active,clk:clk_set_rate,cpu-migrations,cs,dma_fence:dma_fence_init,fib:fib_table_lookup,filemap:mm_filemap_add_to_page_cache,gpio:gpio_value,ipi:ipi_raise,irq:irq_handler_entry,irq:softirq_entry,jbd2:jbd2_handle_start,jbd2:jbd2_start_commit,kmem:kfree,kmem:kmalloc,kmem:kmem_cache_alloc,kmem:kmem_cache_free,kmem:mm_page_alloc,kmem:mm_page_alloc_zone_locked,kmem:mm_page_free,kmem:mm_page_pcpu_drain,mmc:mmc_request_start,net:net_dev_queue,net:net_dev_xmit,net:netif_rx,page-faults,pagemap:mm_lru_insertion,preemptirq:irq_enable,qdisc:qdisc_dequeue,qdisc:qdisc_dequeue,random:get_random_bytes,random:mix_pool_bytes_nolock,random:urandom_read,raw_syscalls:sys_enter,raw_syscalls:sys_exit,rpm:rpm_resume,rpm:rpm_suspend,sched:sched_process_exec,sched:sched_process_free,sched:sched_process_wait,sched:sched_switch,sched:sched_wakeup,signal:signal_deliver,signal:signal_generate,skb:consume_skb,skb:consume_skb,skb:kfree_skb,skb:kfree_skb,skb:skb_copy_datagram_iovec,sock:inet_sock_set_state,task:task_newtask,tcp:tcp_destroy_sock,tcp:tcp_probe,timer:hrtimer_start,timer:timer_start,udp:udp_fail_queue_rcv_skb,workqueue:workqueue_activate_work,writeback:global_dirty_state,writeback:sb_clear_inode_writeback,writeback:wbc_writepage,writeback:writeback_dirty_inode,writeback:writeback_dirty_inode_enqueue,writeback:writeback_dirty_page,writeback:writeback_mark_inode_dirty,writeback:writeback_pages_written,writeback:writeback_single_inode,writeback:writeback_write_inode,writeback:writeback_written".format(
    CPU_HEADERS, TASKS_HEADERS, MEM_HEADERS, SWAP_HEADERS, NETWORK_HEADERS)


def find_duplicate_headers():
    headers = CSV_HEADERS.split(",")
    print("original:", len(headers))
    unique = set(headers)
    print("unique:", len(unique))
    diff = deepcopy(headers)
    for head in unique:
        diff.remove(head)
    print(len(diff), diff)


def prepare_csv_file(behavior):
    csv_file_name = "{}-behavior.csv".format(behavior)
    csv_file_path = os.path.join(fp_dir, csv_file_name)

    if os.path.exists(csv_file_path):
        print("Removing existing CSV file", csv_file_name)
        os.remove(csv_file_path)

    print("Creating new CSV file", csv_file_name)
    with open(csv_file_path, "x"):
        pass

    return csv_file_path


def write_contents(contents, file_path):
    with open(file_path, "w") as file:
        file.write(CSV_HEADERS + "\n")
        for line in contents:
            file.write(line + "\n")


def verify_contents(file_path):
    header_length = len(CSV_HEADERS.split(","))
    with open(file_path, "r") as file:
        for line in file:
            line_length = len(line.split(","))
            assert line_length == header_length, \
                "Line length {} did not match header length {} in line {}".format(line_length, header_length, line)
        print("Verification: all good.")


if __name__ == "__main__":
    print("Find duplicate headers.")
    find_duplicate_headers()

    print("Reading file contents.")
    for directory in fp_dirs:
        files = os.listdir(directory)
        all_lines = []
        for file in files:
            file_path = os.path.join(directory, file)
            with open(file_path, "r") as f:
                fp = f.readline().replace("[", "").replace("]", "").replace(" ", "")
                all_lines.append(fp)

        behavior = os.path.basename(directory)
        print("Preparing CSV file for", behavior, "behavior.")
        csv_file_path = prepare_csv_file(behavior)

        print("Writing contents to CSV.")
        write_contents(all_lines, csv_file_path)
        print("Verifying CSV contents.")
        verify_contents(csv_file_path)
        print("Done with", behavior, "behavior.")
