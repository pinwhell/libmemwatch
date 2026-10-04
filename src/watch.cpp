#include "memwatch/watch.hpp"
#include "memwatch/thr.hpp"
#include "memwatch/remote.hpp"
#include "memwatch/internal.hpp"
#include "memwatch/api.hpp"

#include <cerrno>
#include <cstring>
#include <sys/mman.h>
#include <sys/ptrace.h>

namespace {

rc_t capture_prot(mw_ctx_t *ctx, uintptr_t p0, size_t pcount,
                  std::vector<int> *out) {
  std::vector<mw_map_t> maps;
  rc_t r = mw_read_maps(ctx->pid, &maps);
  if (r != rc_t::ok) {
    return r;
  }
  out->assign(pcount, 0);
  for (size_t i = 0; i < pcount; ++i) {
    uintptr_t a = p0 + (i * ctx->page_size);
    bool found = false;
    for (size_t k = 0; k < maps.size(); ++k) {
      if (a >= maps[k].lo && a < maps[k].hi) {
        (*out)[i] = maps[k].prot;
        found = true;
        break;
      }
    }
    if (!found) {
      mw_log("page 0x%lx is not mapped in the target", a);
      return rc_t::err_range;
    }
  }
  return rc_t::ok;
}

/* Restore one contiguous run of pages that share the same original prot. */
rc_t restore_run(mw_ctx_t *ctx, const mw_watch_t *w, size_t from, size_t to) {
  return mw_remote_mprotect(ctx, w->p0.addr + (from * ctx->page_size),
                            (to - from) * ctx->page_size, w->prot[from]);
}

rc_t enter_critical(mw_ctx_t *ctx) {
  rc_t r;
  ctx->st = mw_state_t::entering;
  r = mw_thr_stop_all(ctx);
  if (r != rc_t::ok) {
    ctx->st = mw_state_t::idle;
    return r;
  }
  ctx->st = mw_state_t::critical;
  return mw_inv_check(ctx, "enter_critical");
}

rc_t leave_critical(mw_ctx_t *ctx) {
  rc_t r = mw_thr_resume_all(ctx, true);
  ctx->st = mw_state_t::idle;
  (void)mw_inv_check(ctx, "leave_critical");
  return r;
}

} /* namespace */

/* ------------------------------------------------------------- inspection */

mw_watch_t *mw_watch_covering_armed(mw_ctx_t *ctx, uintptr_t addr) {
  for (size_t i = 0; i < ctx->ws.size(); ++i) {
    mw_watch_t *w = &ctx->ws[i];
    if (w->armed && rng_covers(w->r, addr)) {
      return w;
    }
  }
  return nullptr;
}

mw_watch_t *mw_watch_find(mw_ctx_t *ctx, uintptr_t base, size_t size) {
  for (size_t i = 0; i < ctx->ws.size(); ++i) {
    if (ctx->ws[i].r.base == base && ctx->ws[i].r.size == size) {
      return &ctx->ws[i];
    }
  }
  return nullptr;
}

bool mw_watch_page_free(const mw_ctx_t *ctx, uintptr_t p0, size_t pcount) {
  uintptr_t lo = p0;
  uintptr_t hi = p0 + (pcount * ctx->page_size);
  for (size_t i = 0; i < ctx->ws.size(); ++i) {
    uintptr_t wlo = ctx->ws[i].p0.addr;
    uintptr_t whi = ctx->ws[i].p0.addr + (ctx->ws[i].pcount * ctx->page_size);
    if (lo < whi && wlo < hi) {
      return false;
    }
  }
  return true;
}

/* ------------------------------------------------------------ armed flips */

rc_t mw_watch_arm(mw_ctx_t *ctx, mw_watch_t *w) {
  rc_t r = mw_remote_mprotect(ctx, w->p0.addr, w->pcount * ctx->page_size,
                              PROT_NONE);
  if (r != rc_t::ok) {
    return r;
  }
  /* Invariant 6: armed only after PROT_NONE is really installed. */
  w->armed = true;
  mw_log("watch [%lx,+%zu) armed", static_cast<unsigned long>(w->r.base),
         w->r.size);
  return rc_t::ok;
}

rc_t mw_watch_disarm(mw_ctx_t *ctx, mw_watch_t *w) {
  size_t i = 0;
  /* Invariant 7: ownership is released before PROT_NONE is removed. */
  if (!w->armed) {
    return rc_t::ok;
  }
  w->armed = false;
  while (i < w->pcount) {
    size_t j = i + 1;
    while (j < w->pcount && w->prot[j] == w->prot[i]) {
      ++j;
    }
    {
      rc_t r = restore_run(ctx, w, i, j);
      if (r != rc_t::ok) {
        mw_log("restoring protection of watch at 0x%lx failed; re-arming",
               static_cast<unsigned long>(w->r.base));
        if (mw_remote_mprotect(ctx, w->p0.addr,
                               w->pcount * ctx->page_size,
                               PROT_NONE) == rc_t::ok) {
          w->armed = true;
        } else {
          mw_poison(ctx, rc_t::err_mprotect, "watch_disarm");
        }
        return r;
      }
    }
    i = j;
  }
  mw_log("watch [%lx,+%zu) disarmed", static_cast<unsigned long>(w->r.base),
         w->r.size);
  return rc_t::ok;
}

rc_t mw_watch_restore_all(mw_ctx_t *ctx) {
  rc_t first = rc_t::ok;
  for (size_t i = 0; i < ctx->ws.size(); ++i) {
    if (!ctx->ws[i].armed) {
      continue;
    }
    {
      rc_t r = mw_watch_disarm(ctx, &ctx->ws[i]);
      if (r != rc_t::ok && first == rc_t::ok) {
        first = r;
      }
    }
  }
  return first;
}

/* ------------------------------------------------------------- public API */

rc_t mw_watch_add(mw_ctx_t *ctx, uintptr_t base, size_t size, mw_cb_t cb,
                  void *ud) {
  size_t pcount;
  pg_t p0;
  std::vector<int> prot;
  rc_t r;

  if (ctx == nullptr) {
    return rc_t::err_invalid;
  }
  if (!ctx->attached) {
    return rc_t::err_state;
  }
  if (ctx->poisoned) {
    return rc_t::err_poisoned;
  }
  if (ctx->st != mw_state_t::idle) {
    mw_log("watch_add refused: state is not idle");
    return rc_t::err_state;
  }
  if (cb == nullptr || size == 0) {
    return rc_t::err_invalid;
  }
  if (base == 0 || base + size < base) {
    return rc_t::err_range;
  }
  pcount = mw_page_count(base, size, ctx->page_size);
  if (pcount == 0) {
    return rc_t::err_range;
  }
  p0 = pg_align_down(base, ctx->page_size);
  if (!mw_watch_page_free(ctx, p0.addr, pcount)) {
    mw_log("watch_add refused: range overlaps an existing watch");
    return rc_t::err_already;
  }
  r = capture_prot(ctx, p0.addr, pcount, &prot);
  if (r != rc_t::ok) {
    return r;
  }

  r = enter_critical(ctx);
  if (r != rc_t::ok) {
    return r;
  }

  /* The target was executing while we captured the protections; re-read them so
   * that the saved prot really is what the pages will need on restore. */
  {
    std::vector<int> prot2;
    r = capture_prot(ctx, p0.addr, pcount, &prot2);
    if (r != rc_t::ok) {
      (void)leave_critical(ctx);
      return r;
    }
    prot.swap(prot2);
  }

  mw_watch_t w{};
  w.r.base = base;
  w.r.size = size;
  w.p0 = p0;
  w.pcount = pcount;
  w.armed = false;
  w.prot.swap(prot);
  w.cb = cb;
  w.ud = ud;

  r = mw_watch_arm(ctx, &w);
  if (r != rc_t::ok) {
    (void)leave_critical(ctx);
    return r;
  }
  ctx->ws.push_back(w);
  return leave_critical(ctx);
}

rc_t mw_watch_del(mw_ctx_t *ctx, uintptr_t base, size_t size) {
  size_t idx = 0;
  rc_t r;
  bool found = false;

  if (ctx == nullptr) {
    return rc_t::err_invalid;
  }
  if (!ctx->attached) {
    return rc_t::err_state;
  }
  if (ctx->st != mw_state_t::idle) {
    return rc_t::err_state;
  }
  for (size_t i = 0; i < ctx->ws.size(); ++i) {
    if (ctx->ws[i].r.base == base && ctx->ws[i].r.size == size) {
      idx = i;
      found = true;
      break;
    }
  }
  if (!found) {
    return rc_t::err_not_found;
  }

  r = enter_critical(ctx);
  if (r != rc_t::ok) {
    return r;
  }
  r = mw_watch_disarm(ctx, &ctx->ws[idx]);
  if (r != rc_t::ok) {
    /* armed still reflects the pages; keep the watch so the user can retry. */
    (void)leave_critical(ctx);
    return r;
  }
  ctx->ws.erase(ctx->ws.begin() + static_cast<long>(idx));
  return leave_critical(ctx);
}

rc_t mw_watch_del_all(mw_ctx_t *ctx) {
  rc_t r;
  rc_t first = rc_t::ok;
  if (ctx == nullptr) {
    return rc_t::err_invalid;
  }
  if (!ctx->attached) {
    return rc_t::err_state;
  }
  if (ctx->st != mw_state_t::idle) {
    return rc_t::err_state;
  }
  if (ctx->ws.empty()) {
    return rc_t::ok;
  }
  r = enter_critical(ctx);
  if (r != rc_t::ok) {
    return r;
  }
  for (size_t i = 0; i < ctx->ws.size(); ++i) {
    rc_t rr = mw_watch_disarm(ctx, &ctx->ws[i]);
    if (rr != rc_t::ok) {
      if (first == rc_t::ok) {
        first = rr;
      }
      mw_log("mw_watch_del_all: watch %zu could not be restored", i);
    }
  }
  if (first == rc_t::ok) {
    ctx->ws.clear();
  }
  {
    rc_t rr = leave_critical(ctx);
    if (rr != rc_t::ok && first == rc_t::ok) {
      first = rr;
    }
  }
  return first;
}
