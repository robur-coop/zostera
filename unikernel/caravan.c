#include <caml/mlvalues.h>

#define CARAVAN_STATE 16
#define CARAVAN_KEY 20
#define CARAVAN_KEY_LEN 32
#define CARAVAN_SLOT_LEN 52 /* "zostera:key-slot" + "NONE" + 32 bytes */

__attribute__((used, aligned(16)))
static volatile const unsigned char slot[CARAVAN_SLOT_LEN] =
    "zostera:key-slot" "NONE";

value caravan(value vbuf) {
  unsigned char *buf = (unsigned char *)Bytes_val(vbuf);
  int i;

  if (slot[CARAVAN_STATE + 0] != 'K' || slot[CARAVAN_STATE + 1] != 'E' ||
      slot[CARAVAN_STATE + 2] != 'Y' || slot[CARAVAN_STATE + 3] != '!')
    return Val_false;

  for (i = 0; i < CARAVAN_KEY_LEN; i++)
    buf[i] = slot[CARAVAN_KEY + i];

  return Val_true;
}
