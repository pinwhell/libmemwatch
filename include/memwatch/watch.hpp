/* libmemwatch - watch management.
 *
 * armed is the ownership guard for PROT_NONE and is written in exactly two
 * places, both in this file:
 *   mw_watch_arm()     -> PROT_NONE installed, then armed = true
 *   mw_watch_disarm()  -> armed = false, then original protection restored
 */
#ifndef MEMWATCH_WATCH_HPP
#define MEMWATCH_WATCH_HPP

#include "memwatch/types.hpp"

mw_watch_t *mw_watch_covering_armed(mw_ctx_t *ctx, uintptr_t addr);
mw_watch_t *mw_watch_find(mw_ctx_t *ctx, uintptr_t base, size_t size);
bool        mw_watch_page_free(const mw_ctx_t *ctx, uintptr_t page,
                               size_t pcount);

/* Install PROT_NONE over the whole watch, then set armed. */
rc_t mw_watch_arm(mw_ctx_t *ctx, mw_watch_t *w);
/* Release ownership first, then restore each page's original protection.
 * If any restore fails the watch is re-armed so that armed never lies. */
rc_t mw_watch_disarm(mw_ctx_t *ctx, mw_watch_t *w);

rc_t mw_watch_restore_all(mw_ctx_t *ctx);

#endif /* MEMWATCH_WATCH_HPP */
