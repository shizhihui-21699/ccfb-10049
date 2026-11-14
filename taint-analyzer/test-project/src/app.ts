import express from 'express';
import { getUser, listUsers, searchUsers, getUserByName, getUserByAge } from './controllers/userController';
import { download, readTemplateFile, upload } from './controllers/fileController';
import { pingHost, reloadNginx, restartService, listLogs } from './controllers/systemController';

const app = express();
app.use(express.json());

app.get('/users/:id', getUser);
app.get('/users', listUsers);
app.get('/search', searchUsers);
app.get('/users/by-name', getUserByName);
app.get('/users/by-age', getUserByAge);
app.get('/download', download);
app.get('/template', readTemplateFile);
app.post('/upload', upload);
app.get('/ping', pingHost);
app.post('/nginx/reload', reloadNginx);
app.post('/restart', restartService);
app.get('/logs', listLogs);

app.listen(3000);
