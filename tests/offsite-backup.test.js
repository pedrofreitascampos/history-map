// Offsite S3/R2 backup mirror — static source tests.
// The S3 upload is a soft side-effect of runBackup(), so these tests verify
// the structural guarantees (env-gated client init, upload call, soft failure,
// correct S3 key pattern) without needing real AWS credentials.

const fs = require('fs');
const path = require('path');

const serverSrc = fs.readFileSync(path.join(__dirname, '..', 'server', 'index.js'), 'utf-8');

describe('Offsite backup — S3 client setup', () => {
  test('S3Client and PutObjectCommand are imported', () => {
    expect(serverSrc).toContain("require('@aws-sdk/client-s3')");
    expect(serverSrc).toContain('S3Client');
    expect(serverSrc).toContain('PutObjectCommand');
  });

  test('_s3Client is null when env vars are absent (opt-in guard)', () => {
    // The ternary checks all three required vars before constructing the client.
    expect(serverSrc).toMatch(/_s3Client\s*=\s*\(_s3Bucket\s*&&\s*process\.env\.BACKUP_S3_ACCESS_KEY\s*&&\s*process\.env\.BACKUP_S3_SECRET_KEY\)/);
  });

  test('S3 endpoint and forcePathStyle are configurable for R2/Minio', () => {
    const initIdx = serverSrc.indexOf('new S3Client(');
    const block = serverSrc.slice(initIdx, initIdx + 400);
    expect(block).toContain('BACKUP_S3_ENDPOINT');
    expect(block).toContain('forcePathStyle');
    expect(block).toContain('BACKUP_S3_REGION');
  });
});

describe('Offsite backup — _uploadBackupToS3 helper', () => {
  test('_uploadBackupToS3 is defined', () => {
    expect(serverSrc).toContain('async function _uploadBackupToS3(');
  });

  test('no-ops when _s3Client is null', () => {
    const fnStart = serverSrc.indexOf('async function _uploadBackupToS3(');
    const fnSlice = serverSrc.slice(fnStart, fnStart + 200);
    expect(fnSlice).toMatch(/if\s*\(!_s3Client\)\s*return/);
  });

  test('sends PutObjectCommand with ContentType application/json', () => {
    const fnStart = serverSrc.indexOf('async function _uploadBackupToS3(');
    const fnSlice = serverSrc.slice(fnStart, fnStart + 300);
    expect(fnSlice).toContain('PutObjectCommand');
    expect(fnSlice).toContain("ContentType: 'application/json'");
  });
});

describe('Offsite backup — runBackup() integration', () => {
  test('runBackup calls _uploadBackupToS3 after local write', () => {
    const fnStart = serverSrc.indexOf('async function runBackup()');
    const fnEnd = serverSrc.indexOf('\nasync function ', fnStart + 10);
    const fnSlice = serverSrc.slice(fnStart, fnEnd);
    expect(fnSlice).toContain('_uploadBackupToS3');
  });

  test('S3 key uses oikumene/<date>/<userId>_<date>.json pattern', () => {
    const fnStart = serverSrc.indexOf('async function runBackup()');
    const fnEnd = serverSrc.indexOf('\nasync function ', fnStart + 10);
    const fnSlice = serverSrc.slice(fnStart, fnEnd);
    expect(fnSlice).toMatch(/`oikumene\/\$\{date\}\/\$\{userId\}_\$\{date\}\.json`/);
  });

  test('S3 upload is fire-and-forget (soft failure — does not await in main flow)', () => {
    const fnStart = serverSrc.indexOf('async function runBackup()');
    const fnEnd = serverSrc.indexOf('\nasync function ', fnStart + 10);
    const fnSlice = serverSrc.slice(fnStart, fnEnd);
    // .then/.catch pattern (not await) so a slow/failing upload never blocks local backup
    expect(fnSlice).toMatch(/_uploadBackupToS3[\s\S]{0,100}\.then\(/);
    expect(fnSlice).toMatch(/\.catch\(err =>/);
  });

  test('S3 failure is logged as backup_s3_failed (not thrown)', () => {
    const fnStart = serverSrc.indexOf('async function runBackup()');
    const fnEnd = serverSrc.indexOf('\nasync function ', fnStart + 10);
    const fnSlice = serverSrc.slice(fnStart, fnEnd);
    expect(fnSlice).toContain("'backup_s3_failed'");
  });

  test('env.example documents all five S3 env vars', () => {
    const envExample = fs.readFileSync(path.join(__dirname, '..', '.env.example'), 'utf-8');
    expect(envExample).toContain('BACKUP_S3_BUCKET');
    expect(envExample).toContain('BACKUP_S3_ACCESS_KEY');
    expect(envExample).toContain('BACKUP_S3_SECRET_KEY');
    expect(envExample).toContain('BACKUP_S3_ENDPOINT');
    expect(envExample).toContain('BACKUP_S3_REGION');
  });
});
