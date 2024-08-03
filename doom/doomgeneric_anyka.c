#include "doomgeneric.h"
#include "doomkeys.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>

#define YUV_BUFFER_FILENAME "/tmp/doom_yuv.bin"
#define YUV_BUFFER_SIZE 345600

// | right | left | forward | backward | fire | use | escape | enter |
#define KEY_STATUS_FILENAME "/tmp/keystatus.bin"
#define KEY_STATUS_SIZE 8

#define KEYQUEUE_SIZE 16

static unsigned short s_KeyQueue[KEYQUEUE_SIZE];
static unsigned int s_KeyQueueWriteIndex = 0;
static unsigned int s_KeyQueueReadIndex = 0;

typedef enum {
    ANYKA_RIGHT,
    ANYKA_LEFT,
    ANYKA_FORWARD,
    ANYKA_BACKWARD,
    ANYKA_FIRE,
    ANYKA_USE,
    ANYKA_ESCAPE,
    ANYKA_ENTER
} ANYKA_DOOM_KEY;

char *shared_yuv_buffer;
char *key_status;
char *last_key_status;

uint8_t y_lookup_red[256];
uint8_t y_lookup_green[256];
uint8_t y_lookup_blue[256];
uint8_t u_lookup_red[256];
uint8_t u_lookup_green[256];
uint8_t u_lookup_blue[256];
uint8_t v_lookup_red[256];
uint8_t v_lookup_green[256];
uint8_t v_lookup_blue[256];

// Function to precompute lookup tables
void precomputeLookupTables() {
    const double kr = 0.299;
    const double kg = 0.587;
    const double kb = 0.114;

    for (int i = 0; i < 256; ++i) {
        y_lookup_red[i] = (uint8_t) (0.299 * i);
        y_lookup_green[i] = (uint8_t) (0.587 * i);
        y_lookup_blue[i] = (uint8_t) (0.114 * i);
        u_lookup_red[i] = (uint8_t) (0.147 * i);
        u_lookup_green[i] = (uint8_t) (0.289 * i);
        u_lookup_blue[i] = (uint8_t) (0.436 * i);
        v_lookup_red[i] = (uint8_t) (0.615 * i);
        v_lookup_green[i] = (uint8_t) (0.515 * i);
        v_lookup_blue[i] = (uint8_t) (0.1 * i);
    }
}

static unsigned char convertToDoomKey(unsigned int key)
{
	switch (key)
	{
    case ANYKA_ENTER:
      key = KEY_ENTER;
      break;
    case ANYKA_ESCAPE:
      key = KEY_ESCAPE;
      break;
    case ANYKA_LEFT:
      key = KEY_LEFTARROW;
      break;
    case ANYKA_RIGHT:
      key = KEY_RIGHTARROW;
      break;
    case ANYKA_FORWARD:
      key = KEY_UPARROW;
      break;
    case ANYKA_BACKWARD:
      key = KEY_DOWNARROW;
      break;
    case ANYKA_FIRE:
      key = KEY_FIRE;
      break;
    case ANYKA_USE:
      key = KEY_USE;
      break;
    default:
      key = tolower(key);
      break;
	}

	return key;
}

static void addKeyToQueue(int pressed, unsigned int keyCode)
{
	unsigned char key = convertToDoomKey(keyCode);

	unsigned short keyData = (pressed << 8) | key;

	s_KeyQueue[s_KeyQueueWriteIndex] = keyData;
	s_KeyQueueWriteIndex++;
	s_KeyQueueWriteIndex %= KEYQUEUE_SIZE;
}

int DG_GetKey(int* pressed, unsigned char* doomKey)
{
	if (s_KeyQueueReadIndex == s_KeyQueueWriteIndex)
	{
		//key queue is empty

		return 0;
	}
	else
	{
		unsigned short keyData = s_KeyQueue[s_KeyQueueReadIndex];
		s_KeyQueueReadIndex++;
		s_KeyQueueReadIndex %= KEYQUEUE_SIZE;

		*pressed = keyData >> 8;
		*doomKey = keyData & 0xFF;

		return 1;
	}
}

void DG_Init()
{
    printf("Initing!\n");
    precomputeLookupTables();

    int fd;

    // initialise the shared yuv data buffer
    fd = open(YUV_BUFFER_FILENAME, O_CREAT | O_RDWR, 0666);
    if (fd == -1) {
        perror("open");
        exit(1);
    }

    if (ftruncate(fd, YUV_BUFFER_SIZE) == -1) {
        perror("ftruncate");
        exit(1);
    }

    // Map the yuv buffer into memory
    shared_yuv_buffer = mmap(NULL, YUV_BUFFER_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (shared_yuv_buffer == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }

    last_key_status = (char*) calloc(KEY_STATUS_SIZE, sizeof(uint8_t));

    // now initialise the shared key buffer in a similar way
    // initialise the shared yuv data buffer
    fd = open(KEY_STATUS_FILENAME, O_CREAT | O_RDWR, 0666);
    if (fd == -1) {
        perror("open");
        exit(1);
    }

    if (ftruncate(fd, KEY_STATUS_SIZE) == -1) {
        perror("ftruncate");
        exit(1);
    }

    // Map the yuv buffer into memory
    key_status = mmap(NULL, KEY_STATUS_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (key_status == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }
}

void DG_DrawFrame() {
    int input_height = 200;
    int output_height = 360;
    int input_width = 320;
    int output_width = 640;

    int output_total = output_width * output_height;

    // Variables to measure time
    struct timespec start_time, end_time;
    uint32_t time_to_draw;

    // Record start time
    clock_gettime(CLOCK_MONOTONIC, &start_time);

    // Upscale DG_ScreenBuffer to 640x360 and store it in shared_yuv_buffer
    for (int i = 0; i < output_height; i+=2) {
        for (int j = 0; j < output_width; j+=2) {
            // Mapping coordinates from output to input
            int x_input = j * input_width / output_width;
            int y_input = i * input_height / output_height;

            // Accessing pixel in the input buffer
            uint32_t centerPixel = DG_ScreenBuffer[y_input * input_width + x_input];

            uint8_t red = centerPixel >> 16;
            uint8_t green = centerPixel >> 8;
            uint8_t blue = centerPixel;

            uint8_t new_y = y_lookup_red[red] + y_lookup_green[green] + y_lookup_blue[blue];
            shared_yuv_buffer[i * output_width + j] = new_y;
            shared_yuv_buffer[(i+1) * output_width + j] = new_y;
            shared_yuv_buffer[i * output_width + (j+1)] = new_y;
            shared_yuv_buffer[(i+1) * output_width + (j+1)] = new_y;

            // Calculate offset for U and V channels
            int offset = (i / 2) * (output_width / 2) + (j / 2);
            int offset2 = (i / 2) * (output_width / 2) + ((j + 1) / 2);
            int offset3 = ((i+1) / 2) * (output_width / 2) + (j / 2);
            int offset4 = ((i+1) / 2) * (output_width / 2) + ((j + 1) / 2);

            uint8_t new_u = -u_lookup_red[red] - u_lookup_green[green] + u_lookup_blue[blue] + 128;
            shared_yuv_buffer[output_total + offset] = new_u;
            shared_yuv_buffer[output_total + offset2] = new_u;
            shared_yuv_buffer[output_total + offset3] = new_u;
            shared_yuv_buffer[output_total + offset4] = new_u;

            uint8_t new_v = v_lookup_red[red] - v_lookup_green[green] - v_lookup_blue[blue] + 128;
            shared_yuv_buffer[output_total + output_total / 4 + offset] = new_v;
            shared_yuv_buffer[output_total + output_total / 4 + offset2] = new_v;
            shared_yuv_buffer[output_total + output_total / 4 + offset3] = new_v;
            shared_yuv_buffer[output_total + output_total / 4 + offset4] = new_v;
        }
    }

    // Record end time
    clock_gettime(CLOCK_MONOTONIC, &end_time);

    // Calculate time taken
    time_to_draw = (end_time.tv_sec - start_time.tv_sec) * 1000 + (end_time.tv_nsec - start_time.tv_nsec) / 1000000;

    // printf("Frame drawn in %d ms\n", time_to_draw);

    // check for changes in the key status
    for (int i = 0; i < KEY_STATUS_SIZE; i++) {
        if (key_status[i] != last_key_status[i]) {
            if (key_status[i] == 1) { // key pressed
                addKeyToQueue(1, i);
            } else { // key released
                addKeyToQueue(0, i);
            }
            last_key_status[i] = key_status[i];
        }
    }
}

void DG_SleepMs(uint32_t ms)
{
  usleep (ms * 1000);
}

uint32_t DG_GetTicksMs()
{
  struct timeval  tp;
  struct timezone tzp;

  gettimeofday(&tp, &tzp);

  return (tp.tv_sec * 1000) + (tp.tv_usec / 1000); /* return milliseconds */
}

void DG_SetWindowTitle(const char * title)
{
  printf("Setting window title");
}

int main(int argc, char **argv)
{
  printf("Running doom!\n");
    doomgeneric_Create(argc, argv);

    for (int i = 0; ; i++)
    {
        doomgeneric_Tick();
    }
    

    return 0;
}