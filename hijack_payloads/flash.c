#include <stdint.h>

#define SET_LIGHT_SWITCH_MODE_ADDR 0x3bfe8
#define SLEEP_ADDR 0x192a0

typedef enum {
    YI_LIGHT_SWITCH_ALWAYS_OFF,
    YI_LIGHT_SWITCH_ALWAYS_ON,
    YI_LIGHT_SWITCH_AUTO_MODE
} YI_LIGHT_SWITCH_MODE;

typedef int yi_p2p_on_set_light_switch_mode_t(YI_LIGHT_SWITCH_MODE mode);
typedef uint32_t sleep_t(uint32_t seconds);

int _start(void) {
    yi_p2p_on_set_light_switch_mode_t *yi_p2p_on_set_light_switch_mode = (yi_p2p_on_set_light_switch_mode_t *) SET_LIGHT_SWITCH_MODE_ADDR;
    sleep_t *sleep = (sleep_t*) SLEEP_ADDR;

    char flippy = 0;
    while(1){
        YI_LIGHT_SWITCH_MODE new_mode;
        if (flippy == 0){
            new_mode = YI_LIGHT_SWITCH_ALWAYS_ON;
            flippy = 1;
        } else {
            new_mode = YI_LIGHT_SWITCH_ALWAYS_OFF;
            flippy = 0;
        }
        yi_p2p_on_set_light_switch_mode(new_mode);
        sleep(2);
    }
}