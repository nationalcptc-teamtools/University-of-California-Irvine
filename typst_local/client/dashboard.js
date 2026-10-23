import { api, h, timeAgo, dialog, popupMenu, toast, getUser, saveUser, ensureUserName, initials } from './lib/common.js';

const listEl = document.getElementById('projects');
const userBtn = document.getElementById('user-btn');

let templates = [];

function renderUser() {
  const user = getUser();
  userBtn.replaceChildren(
    h('span.avatar', { style: { background: user.color } }, initials(user.name)),
    h('span', null, user.name || 'Set name'),
  );
}

userBtn.onclick = async () => {
  const user = getUser();
  const res = await dialog({
    title: 'Your profile',
    fields: [{ name: 'name', label: 'Display name', value: user.name }],
    confirm: 'Save',
  });
  if (!res) return;
  user.name = res.name.trim().slice(0, 40) || user.name;
  saveUser(user);
  renderUser();
};

async function newProject() {
  if (!templates.length) templates = await api('GET', '/api/templates');
  const res = await dialog({
    title: 'New project',
    fields: [
      { name: 'name', label: 'Project name', value: 'Untitled' },
      { name: 'template', label: 'Template', options: templates.map((t) => ({ value: t.id, label: t.label })), value: 'article' },
    ],
    confirm: 'Create',
  });
  if (!res) return;
  const meta = await api('POST', '/api/projects', { name: res.name, template: res.template });
  location.href = '/project/' + meta.id;
}

document.getElementById('new-btn').onclick = newProject;

function projectMenu(e, p) {
  e.preventDefault();
  e.stopPropagation();
  popupMenu(e.currentTarget.closest('.card-menu') ? e.currentTarget : e, [
    {
      label: 'Rename',
      onclick: async () => {
        const res = await dialog({ title: 'Rename project', fields: [{ name: 'name', value: p.name }], confirm: 'Rename' });
        if (res?.name.trim()) {
          await api('PATCH', `/api/projects/${p.id}`, { name: res.name });
          load();
        }
      },
    },
    {
      label: 'Duplicate',
      onclick: async () => {
        await api('POST', `/api/projects/${p.id}/duplicate`);
        load();
      },
    },
    { label: 'Download PDF', onclick: () => (location.href = `/api/projects/${p.id}/pdf`) },
    { label: 'Download Word (.docx)', onclick: () => (location.href = `/api/projects/${p.id}/docx`) },
    { label: 'Download source (.zip)', onclick: () => (location.href = `/api/projects/${p.id}/zip`) },
    'sep',
    {
      label: 'Delete',
      danger: true,
      onclick: async () => {
        const ok = await dialog({
          title: 'Delete project?',
          message: `"${p.name}" and all of its files will be permanently deleted for everyone.`,
          confirm: 'Delete',
          danger: true,
        });
        if (!ok) return;
        await api('DELETE', `/api/projects/${p.id}`);
        toast('Project deleted');
        load();
      },
    },
  ]);
}

async function load() {
  const projects = await api('GET', '/api/projects');
  if (!projects.length) {
    listEl.replaceChildren(
      h(
        'div.empty',
        null,
        h('div.empty-title', null, 'No projects yet'),
        h('p', null, 'Create a project and share the link with your collaborators.'),
        h('button.btn.primary', { onclick: newProject }, 'Create your first project'),
      ),
    );
    return;
  }
  listEl.replaceChildren(
    ...projects.map((p) =>
      h(
        'a.card',
        { href: '/project/' + p.id, oncontextmenu: (e) => projectMenu(e, p) },
        h('div.card-thumb', null, h('div.card-thumb-page', null, h('span', null, p.name))),
        h(
          'div.card-body',
          null,
          h('div.card-text', null, h('div.card-title', null, p.name), h('div.card-sub', null, 'Edited ' + timeAgo(p.updatedAt))),
          h('button.icon-btn.card-menu', { title: 'More', onclick: (e) => projectMenu(e, p), html: '&#8943;' }),
        ),
      ),
    ),
  );
}

renderUser();
load().catch((e) => toast(e.message, 'error'));
ensureUserName().then(renderUser);
