# مسك — Node 22 (مطلوب: الموقع بيستخدم node:sqlite المدمج)
FROM node:22-slim

WORKDIR /app

# الاعتماديات أولاً للاستفادة من الكاش
COPY package*.json ./
RUN npm install --omit=dev && npm cache clean --force

COPY . .

# مجلد البيانات (قاعدة البيانات + الملفات المرفوعة)، ويكون مملوك للمستخدم node (uid 1000) لأن المنصات زي Hugging Face بتشغّل بمستخدم غير root
RUN mkdir -p /data/uploads && chown -R node:node /data /app
ENV PORT=7860 \
    DB_PATH=/data/misk.db \
    UPLOAD_DIR=/data/uploads \
    TRUST_PROXY=1
# مهم: اضبط OWNER_NAME (اسم المالك) من إعدادات المنصة (Variables/Secrets)

USER node
EXPOSE 7860
CMD ["node", "server.js"]
