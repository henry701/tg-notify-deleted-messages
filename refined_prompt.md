<REFINED_PROMPT_ONLY_INSIDE>
Objective: Continue refactoring and modularizing the tg-notify-deleted-messages project to make it genuinely testable, and raise total coverage to at least 50%.

Current baseline (run with `python -m pytest --cov=app/src --cov-report=term-missing -q`):
- 43 passed
- total coverage: 20%
- worst gaps: `app/src/app.py` (0%), `app/src/packages/message_loading.py` (0%), `app/src/packages/telegram_helpers.py` (15%), `app/src/packages/bot_assistant.py` (0%)

Existing extracted modules (do not rewrite): `app/src/packages/filtering.py`, `app/src/packages/message_loading.py`, `app/src/packages/notifications.py`.

Primary goal: Split `app/src/app.py` by separate concerns, add tests until coverage ≥ 50%.

### Step 1: Discovery and Planning
1.1. Run `grep -n "^def \|^async def " app/src/app.py` to list all functions in app.py.
1.2. Categorize each function into one of four concern groups:
   - **Bootstrap/Runtime Wiring**: `make_client`, `configure_bot`, `add_signal_handlers`, `client_main_loop_job`, `create_app_and_start_jobs`, `closer`, `sync_closer`, `worker_function`
   - **HTTP Concerns**: `create_app`, `add_informative_routes`, `before_request`, `/send_code`, `/auth`, `/logout`, `/save_sessions`, `/is_bot_connected`, `/is_connected`, `/is_bot_authorized`, `/is_authorized`, `/health`
   - **Background Jobs**: `clean_old_messages_loop`, `preload_messages`, `gather_with_concurrency`, `preload_messages_for_dialog`, `preload_messages_status_loop`
   - **Deleted-Message Event/Persistence Orchestration**: `add_event_handlers`, `get_on_message_deleted`, `get_on_new_message`, `get_should_ignore_message`, `get_should_ignore_message_chat`, `raw_should_ignore_message_chat` (already in filtering.py), `get_message_media_blob`, `get_store_message`, `get_store_message_if_not_exists`, `should_ignore_deleted_message` (already in filtering.py), `build_peer_entity`, `load_messages_from_deleted_event`, `load_messages_from_db` (already in message_loading.py), `load_messages_by_parameters` (already in message_loading.py), `filter_loaded_messages` (already in message_loading.py)

Note: Some functions are already extracted; skip them.

### Step 2: Extract Bootstrap/Runtime Wiring
2.1. Create new module `app/src/packages/bootstrap.py`.
2.2. Move functions `make_client`, `configure_bot`, `add_signal_handlers`, `client_main_loop_job`, `closer`, `sync_closer`, `worker_function` into `bootstrap.py`.
2.3. Update imports in `app.py` to use `from packages.bootstrap import ...`.
2.4. Ensure the app still runs: `python -c "from app.src.app import main; print('import ok')"` (should not error).

### Step 3: Extract HTTP Concerns
3.1. Create new module `app/src/packages/http.py`.
3.2. Move `create_app` and `add_informative_routes` into `http.py`. Also move nested route functions (or keep them nested but defined within the module). Consider moving the bearer‑auth guard and route definitions as a Flask blueprint.
3.3. Update imports in `app.py` to import the moved functions.
3.4. Verify that the Flask app can still be instantiated (mock dependencies).

### Step 4: Extract Background Jobs
4.1. Create new module `app/src/packages/background_jobs.py`.
4.2. Move `clean_old_messages_loop`, `preload_messages`, `gather_with_concurrency`, `preload_messages_for_dialog`, `preload_messages_status_loop` into `background_jobs.py`.
4.3. Update imports in `app.py`.
4.4. Ensure the functions remain callable.

### Step 5: Extract Deleted-Message Event/Persistence Orchestration
5.1. Create new module `app/src/packages/event_orchestration.py`.
5.2. Move `add_event_handlers`, `get_on_message_deleted`, `get_on_new_message`, `get_should_ignore_message`, `get_should_ignore_message_chat`, `get_message_media_blob`, `get_store_message`, `get_store_message_if_not_exists`, `build_peer_entity`, `load_messages_from_deleted_event` into `event_orchestration.py`.
5.3. Update imports in `app.py`.
5.4. Note: `raw_should_ignore_message_chat` and `should_ignore_deleted_message` are already in `filtering.py`; `load_messages_from_db`, `load_messages_by_parameters`, `filter_loaded_messages` are already in `message_loading.py`. Keep them there.

### Step 6: Write Unit Tests for Extracted Modules
Focus on the largest uncovered surfaces first: `app.py` (now split), `bot_assistant.py`, `telegram_helpers.py`, `message_loading.py`.

6.1. Create test file `tests/test_bootstrap.py` for `bootstrap.py`. Mock TelegramClient, sessionmaker, etc. Test `make_client` (with mocked Telethon), `configure_bot` (with mocked bot token), `add_signal_handlers` (mock loop), `clean_old_messages_loop` (mock session).
6.2. Create test file `tests/test_http.py` for `http.py`. Test route endpoints using Flask test client. Mock TelegramClient and bot. Test bearer‑auth guard, `/send_code`, `/auth`, `/logout`, `/health`, etc.
6.3. Create test file `tests/test_background_jobs.py` for `background_jobs.py`. Test `preload_messages` with mocked client iter_dialogs, `clean_old_messages_loop` with mocked session, `gather_with_concurrency`.
6.4. Create test file `tests/test_event_orchestration.py` for `event_orchestration.py`. Test `add_event_handlers` (mock client.add_event_handler), `get_on_message_deleted` (mock database queries), `get_store_message` (mock session.merge).
6.5. Add tests for `bot_assistant.py` (currently 0% coverage). Create `tests/test_bot_assistant.py`. Mock Telethon client, test `notify_message_deletion`, `notify_unknown_message`.
6.6. Add tests for `telegram_helpers.py` (currently 15% coverage). Extend `tests/test_telegram_helpers.py` (if exists) or create new. Test `build_telegram_peer`, `to_telethon_input_peer`, `format_default_message_text` with mocked client responses.
6.7. Add tests for `message_loading.py` (currently 0% coverage). Create `tests/test_message_loading.py`. Mock SQLAlchemy session and TelegramClient. Test `load_messages_from_db`, `load_messages_by_parameters`, `filter_loaded_messages`.

### Step 7: Verification
7.1. After each extraction, run `python -m pytest --cov=app/src --cov-report=term-missing -q` to ensure tests still pass.
7.2. After adding tests, run the same command to verify coverage increase.
7.3. Target coverage: at least 50% total.
7.4. If any test fails, fix before proceeding.

### Step 8: Final Validation
8.1. Run full test suite: `python -m pytest --cov=app/src --cov-report=term-missing -q`.
8.2. Ensure no regressions: all previous tests still pass.
8.3. Check that the app can still start (optional): `python -c "from app.src.app import main; print('OK')"`.

### Done Criteria
- All extracted modules are in separate files under `app/src/packages/`.
- `app.py` is significantly reduced (only top‑level orchestration).
- Total test coverage ≥ 50% (verified via pytest coverage report).
- All existing tests pass.
- New tests cover at least 80% of each extracted module's public functions.
</REFINED_PROMPT_ONLY_INSIDE>