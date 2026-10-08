# bekhub

## 🔒 Сыр маалыматтардан коргоо

Бул репо ачык. Сырсөздөр, API ачкычтары, токендер, `.env` файлдары жана кардарлардын
жеке маалыматтары репого кирбеши үчүн бир нече катмар коргоо коюлган:

| Катмар | Файл | Качан иштейт |
|---|---|---|
| `.gitignore` | `.gitignore` | `.env`, ачкыч файлдарды жана базаларды git'ке кошпойт |
| Git hook | `.githooks/pre-commit` | ар бир коммиттен мурун |
| Claude hook | `.claude/settings.json` | Claude `git commit` / `git push` кылаардан мурун |
| CI | `.github/workflows/secret-scan.yml` | GitHub'га ар бир пушта (gitleaks бүт тарыхты карайт) |
| Эрежелер | `CLAUDE.md` | Claude сыр тапса, аны тазалайт жана чатта ⚠️ эскертет |

Өз компьютериңизде git hook'ту бир жолу иштетиңиз:

```bash
git config core.hooksPath .githooks
```

Колго текшерүү үчүн: `./scripts/check-secrets.sh --all`

Сыр маанилерди `.env`'ге жазыңыз (`cp .env.example .env`). Ал репого кирбейт.
