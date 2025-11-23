import argparse
import os
import sys
import yaml
import time
import shutil
import logging
import logging.handlers
import json
from pathlib import Path
import tempfile
from datetime import datetime, timezone


def load_config(path):
    with open(path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)

# Настройка логирования, создаем логер с заданным именем и уровнем логирования
# Пытаемся подключиться к системному логеру
def setup_logging(name, level=logging.INFO):
    logger = logging.getLogger(name)
    logger.setLevel(level)
    if not logger.handlers:
        try:
            handler = logging.handlers.SysLogHandler(address='/dev/log')
        except Exception:
            handler = logging.handlers.SysLogHandler(('localhost', 514))
        fmt = logging.Formatter('%(name)s: %(levelname)s: %(message)s')
        handler.setFormatter(fmt)
        logger.addHandler(handler)
    return logger


def write_status(status_path, data):
    try:
        os.makedirs(os.path.dirname(status_path), exist_ok=True)
        with open(status_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logger.error(f"Не удалось записать status_file: {e}")

# создает резервную копию данных из source в dest_dir
def make_backup(source, dest_dir, exclude_patterns=None, dry_run=False):
    ts = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
    target = Path(dest_dir) / f"backup_{ts}"
    if dry_run:
        logger.info(f"DRY RUN: would copy {source} -> {target}")
        return str(target), 0
    os.makedirs(target, exist_ok=True)

    total_files = 0
    total_bytes = 0
# Проходим по всем поддир, файлам
    for root, dirs, files in os.walk(source):
        rel = os.path.relpath(root, source)

        skip = False
        if exclude_patterns:
            for pat in exclude_patterns:
                if Path(rel).match(pat) or Path(root).match(pat):
                    skip = True
                    break
        if skip:
            continue
        tgt_root = Path(target) / rel if rel != '.' else Path(target)
# создаем поддиректории в бэкапе
        os.makedirs(tgt_root, exist_ok=True)
# копируем файлы
        for f in files:
            src_f = Path(root) / f
            if exclude_patterns and any(src_f.match(p) for p in exclude_patterns):
                continue
            dst_f = tgt_root / f
            try:
                shutil.copy2(src_f, dst_f)
                total_files += 1
                total_bytes += src_f.stat().st_size
            except Exception as e:
                logger.warning(f"Ошибка копирования {src_f} -> {dst_f}: {e}")
    return str(target), total_bytes

# сортирует копии в бэкапе и удаляет старые
def rotate_backups(backup_dir, max_backups):
    if max_backups is None:
        return
    entries = sorted([p for p in Path(backup_dir).iterdir() if p.is_dir()])
    while len(entries) > max_backups:
        oldest = entries.pop(0)
        try:
            shutil.rmtree(oldest)
            logger.info(f"Удалена старая резервная копия: {oldest}")
        except Exception as e:
            logger.error(f"Ошибка удаления {oldest}: {e}")


# main
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Backup daemon')
    parser.add_argument('--config', default='/home/vboxuser/Project_mybackup/config.yaml')
    args = parser.parse_args()

    cfg = load_config(args.config)

    log_level = getattr(logging, cfg.get('log_level', 'INFO').upper(), logging.INFO)
    logger = setup_logging('mybackup', log_level)

    source = cfg['source_dir']
    backup_dir = cfg['backup_dir']
    interval = cfg.get('interval_seconds', 3600)
    max_backups = cfg.get('max_backups', 10)
    exclude = cfg.get('exclude_patterns', [])
    dry_run = cfg.get('dry_run', False)
    status_file = cfg.get('status_file', '/var/lib/mybackup/status.json')
    owner_user = cfg.get('owner_user')
    owner_group = cfg.get('owner_group')
    backup_mode = int(cfg.get('backup_dir_mode', 0o700))

# записываем в лог, что демон начал работу и записываем статус
    logger.info('mybackup daemon started')
    write_status(status_file, {
        'state': 'running',
        'source': source,
        'backup_dir': backup_dir,
        'last_backup': None,
        'last_result': None,
    })

    try:
        while True:
            start = datetime.now(timezone.utc).isoformat()
            try:
                # проверяем существование диррект. если нет, то создаем
                if not os.path.exists(source):
                    raise FileNotFoundError(f"Source dir not found: {source}")

                os.makedirs(backup_dir, exist_ok=True)
                # os.chmod(backup_dir, backup_mode)
                # создаем копию
                target, bytes_copied = make_backup(source, backup_dir, exclude_patterns=exclude, dry_run=dry_run)
                # меняем владельца и группу в копии
                if owner_user or owner_group:
                    import pwd, grp
                    uid = pwd.getpwnam(owner_user).pw_uid if owner_user else -1
                    gid = grp.getgrnam(owner_group).gr_gid if owner_group else -1
                    for root, dirs, files in os.walk(target):
                        try:
                            os.chown(root, uid if uid!=-1 else os.stat(root).st_uid, gid if gid!=-1 else os.stat(root).st_gid)
                        except Exception:
                            pass
                # удаляем старые копии
                rotate_backups(backup_dir, max_backups)
                #записываем результат и логируем
                result = {'state': 'ok', 'last_backup': start, 'target': target, 'bytes_copied': bytes_copied}
                logger.info(f"Backup complete -> {target} ({bytes_copied} bytes). Next in {interval} s")
            except Exception as e:
                logger.exception(f"Backup error: {e}")
                result = {'state': 'error', 'last_backup': start, 'error': str(e)}
            # записываем результат в статус файл
            write_status(status_file, result)

            time.sleep(interval)

    except KeyboardInterrupt:
        logger.info('mybackup daemon stopped by KeyboardInterrupt')
        write_status(status_file, {'state': 'stopped'})
        sys.exit(0)
