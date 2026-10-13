/**
 * @file translator.h
 * @desc LLM-backed language services: translation, the eliza moderator
 *       persona, small talk and content moderation. Requests go to Gemini
 *       (when GEMINI_API_KEY is set and Gemini is not cooling down) and fall
 *       back to a local Ollama instance. All functions are thread-safe.
 */
#ifndef SSH_CHATTER_TRANSLATOR_H
#define SSH_CHATTER_TRANSLATOR_H

#include <stdbool.h>
#include <stddef.h>
#include <time.h>

/* ---- Lifecycle ---- */

/**
 * @desc Initialize libcurl and load any persisted Gemini cooldown. Safe to
 *       call repeatedly; every public entry point calls it lazily.
 */
void translator_global_init(void);

/**
 * @desc Release libcurl global state at shutdown.
 */
void translator_global_cleanup(void);

/* ---- Translation ---- */

/**
 * @desc Translate text into target_language, trying each configured
 *       provider in order until one succeeds.
 * @param text              Plain text to translate (no ANSI sequences; see
 *                          translation_prepare_text()).
 * @param target_language   Human-readable target language name.
 * @param translation       Receives the translated text.
 * @param translation_len   Size of translation.
 * @param detected_language Optional; receives the detected source language.
 * @param detected_len      Size of detected_language.
 * @return true on success; on failure see translator_last_error().
 */
bool translator_translate(const char *text, const char *target_language,
                          char *translation, size_t translation_len,
                          char *detected_language, size_t detected_len);

/**
 * @desc Same as translator_translate() but aborts early once *cancel_flag
 *       becomes true (e.g. when the requesting session disconnects).
 * @param cancel_flag Polled during the request; may be nullptr.
 */
bool translator_translate_with_cancel(const char *text,
                                      const char *target_language,
                                      char *translation, size_t translation_len,
                                      char *detected_language,
                                      size_t detected_len,
                                      const volatile bool *cancel_flag);

/* ---- Conversation ---- */

/**
 * @desc Produce a reply in the eliza moderator persona.
 * @param prompt    Conversation prompt.
 * @param reply     Receives the reply text.
 * @param reply_len Size of reply.
 * @return true when any provider produced a reply.
 */
bool translator_eliza_respond(const char *prompt, char *reply,
                              size_t reply_len);

/**
 * @desc Small-talk reply from Ollama only.
 * @param model_name Ollama model; "gemma2:2b" when nullptr or empty.
 */
bool translator_ollama_smalltalk(const char *prompt, const char *model_name,
                                 char *reply, size_t reply_len);

/**
 * @desc Small-talk reply from Gemini only.
 * @param model_name Gemini model; "gemini-2.5-flash-lite" when nullptr or
 *                   empty.
 */
bool translator_gemini_smalltalk(const char *prompt, const char *model_name,
                                 char *reply, size_t reply_len);

/* ---- Moderation ---- */

/**
 * @desc Ask an LLM whether content should be blocked. Cheap pre-checks may
 *       skip the request entirely, and requests are throttled.
 * @param category   Kind of content (chat, BBS post, ...) passed to the
 *                   prompt.
 * @param content    Text to classify; empty text is always allowed.
 * @param blocked    Receives the verdict.
 * @param reason     Receives the provider's reason when blocked.
 * @param reason_len Size of reason.
 * @return true when a verdict was obtained (or not needed), false when every
 *         provider failed.
 */
bool translator_moderate_text(const char *category, const char *content,
                              bool *blocked, char *reason, size_t reason_len);

/* ---- Diagnostics ---- */

/**
 * @desc Last error recorded by any translator call. The returned pointer is
 *       a thread-local snapshot valid until the next call on this thread.
 */
const char *translator_last_error(void);

/**
 * @desc Whether the last error was a provider quota/rate-limit failure.
 */
bool translator_last_error_was_quota(void);

/* ---- Provider control (/gemini, /gemini-unfreeze) ---- */

/**
 * @desc Manually enable or disable Gemini. Enabling also clears any
 *       automatic cooldown.
 */
void translator_set_gemini_enabled(bool enabled);

/**
 * @desc True when Gemini is neither manually disabled nor cooling down.
 */
bool translator_is_gemini_enabled(void);

/**
 * @desc True only when an operator turned Gemini off with /gemini off.
 */
bool translator_is_gemini_manually_disabled(void);

/**
 * @desc Report the automatic Gemini cooldown (set after quota errors, until
 *       local midnight).
 * @param remaining Optional; receives the time left.
 * @return true while the cooldown is active.
 */
bool translator_gemini_backoff_remaining(struct timespec *remaining);

/**
 * @desc Cancel the automatic Gemini cooldown immediately.
 */
void translator_clear_gemini_backoff(void);

/**
 * @desc True when only Ollama is usable (Gemini disabled or no API key).
 */
bool translator_is_ollama_only(void);

/* ---- Translation scope (/translate-scope) ---- */

/**
 * @desc Limit translation to chat and BBS content. Turning this off also
 *       turns off scrollback skipping.
 */
void translator_set_manual_chat_bbs_only(bool enabled);
bool translator_is_manual_chat_bbs_only(void);

/**
 * @desc Skip translating scrollback; only effective while the chat/BBS-only
 *       scope is active.
 */
void translator_set_manual_skip_scrollback(bool enabled);
bool translator_is_manual_skip_scrollback(void);

/**
 * @desc Effective scope check: forced on when running Ollama-only, otherwise
 *       follows the manual setting.
 */
bool translator_should_limit_to_chat_bbs(void);

/**
 * @desc Effective scrollback check: requires both the chat/BBS-only scope
 *       and the skip-scrollback flag.
 */
bool translator_should_skip_scrollback_translation(void);

#endif
