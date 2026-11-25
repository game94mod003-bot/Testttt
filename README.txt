ABULIX Scanner — راهنمای بیلد با گیتهاب

۱) در github.com یک ریپوی جدید بساز (Public یا Private).
۲) Add file > Upload files. «محتوای» این پوشه را بکش و رها کن (نه خود پوشه را).
   پوشه .github هم باید آپلود شود. اگر آپلود نشد: در ریپو Add file > Create new file،
   اسم فایل را .github/workflows/build.yml بنویس و متن فایل github-workflow-build.yml.txt را در آن بچسبان.
۳) Commit changes.
۴) تب Actions > Build APK > Run workflow (یا بعد از commit خودکار اجرا می‌شود).
۵) بعد از ~۳ تا ۵ دقیقه، روی اجرای سبز کلیک کن و از پایین صفحه، Artifacts > Abulix-APK را دانلود کن.
   (یک زیپ است؛ داخلش app-debug.apk را نصب کن.)
