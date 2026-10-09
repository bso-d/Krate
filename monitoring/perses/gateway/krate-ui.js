/*
 * Krate: hide Perses write controls from users who may not change anything.
 *
 * Perses v0.54 always renders the dashboard Edit button and, with its own
 * authorization off (gateway mode), every create/update/delete control. The
 * gateway injects this script into Perses' HTML. It asks /krate/role, which is
 * answered by the same guard and current IdP groups that the server enforces,
 * and hides write controls unless the role is admin. The server still refuses
 * every write by a Viewer; this only keeps the UI consistent with that.
 * Labels and icons match Perses v0.54.0 (ui/app, @perses-dev/dashboards 0.54.0,
 * mdi-material-ui 7.9.3); re-check them when Perses is upgraded.
 */
(function () {
  'use strict';

  var LABELS = [
    // Dashboard toolbar; Edit and Delete also in resource drawers (FormActions)
    'Edit', 'Delete',
    // Home page
    'Create Dashboard', 'Create Project', 'Import Dashboard',
    // Project page
    'Add Dashboard', 'Add Datasource', 'Add Folder', 'Add Role', 'Add Role Binding',
    'Add Secret', 'Add Variable', 'Rename project', 'Delete project',
    // Admin page
    'Add Global Datasource', 'Add Global Role', 'Add Global Role Binding',
    'Add Global Secret', 'Add Global Variable',
  ];
  // Row actions in Perses lists. Grid action items carry the label on the button;
  // CRUDIconButton puts it, through its tooltip, on a span around the button.
  var ROW_ACTIONS = ['Edit', 'Duplicate', 'Delete', 'Rename', 'Add Folder'];
  // Tabs for kinds a Viewer may not read (the guard refuses them; with Perses'
  // authorization off they would show as empty lists).
  var TABS = ['Secrets', 'Roles', 'Role Bindings', 'Global Secrets', 'Global Roles',
    'Global Role Bindings', 'Users'];
  // Perses' own wrapper (CRUDAction) around a control the user lacks permission for;
  // the control inside is then unlabelled.
  var MISSING_PERMISSION = /^Missing '[a-z]+' (global permission|permission in ')/;
  // Icon-only variants on small screens: Pencil, PencilOutline, DeleteOutline.
  var ICON_PATHS = [
    'M20.71,7.04C21.1,6.65 21.1,6 20.71,5.63L18.37,3.29C18,2.9 17.35,2.9 16.96,3.29L15.12,5.12L18.87,8.87M3,17.25V21H6.75L17.81,9.93L14.06,6.18L3,17.25Z',
    'M14.06,9L15,9.94L5.92,19H5V18.08L14.06,9M17.66,3C17.41,3 17.15,3.1 16.96,3.29L15.13,5.12L18.88,8.87L20.71,7.04C21.1,6.65 21.1,6 20.71,5.63L18.37,3.29C18.17,3.09 17.92,3 17.66,3M14.06,6.19L3,17.25V21H6.75L17.81,9.94L14.06,6.19Z',
    'M6,19A2,2 0 0,0 8,21H16A2,2 0 0,0 18,19V7H6V19M8,9H16V19H8V9M15.5,4L14.5,3H9.5L8.5,4H5V6H19V4H15.5Z',
  ];
  // Perses binds edit mode to the key sequence D then M and save to Mod+S
  // (@tanstack/react-hotkeys callbacks, not DOM events), so the keys are blocked.
  var SEQUENCE_WINDOW_MS = 1500;
  var MARK = 'data-krate-viewer-hidden';
  // MUI tab bars watch their first and last tab to show scroll arrows, so a hidden
  // tab stays in the layout with no size instead of being removed from it.
  var TAB_MARK = 'data-krate-viewer-hidden-tab';

  function controlOf(node) {
    return node.closest('button, a, [role="button"], [role="menuitem"]');
  }

  function hide(node) {
    // A control disabled for missing permission sits inside a tooltip span.
    var target = node.parentElement && node.parentElement.tagName === 'SPAN' &&
      node.parentElement.childElementCount === 1 ? node.parentElement : node;
    if (!target.hasAttribute(MARK)) {
      target.setAttribute(MARK, '');
    }
  }

  function scan(root) {
    var controls = root.querySelectorAll('button, a, [role="button"], [role="menuitem"]');
    for (var i = 0; i < controls.length; i++) {
      var control = controls[i];
      var text = (control.textContent || '').trim();
      if (LABELS.indexOf(text) !== -1) {
        hide(control);
      }
    }
    var tabs = root.querySelectorAll('[role="tab"]');
    for (var t = 0; t < tabs.length; t++) {
      // Tab labels end with an item count when there are items, for example "Roles3".
      var tabLabel = (tabs[t].textContent || '').trim().replace(/\d+$/, '');
      if (TABS.indexOf(tabLabel) !== -1 && !tabs[t].hasAttribute(TAB_MARK)) {
        tabs[t].setAttribute(TAB_MARK, '');
      }
    }
    var labelled = root.querySelectorAll('[aria-label]');
    for (var k = 0; k < labelled.length; k++) {
      var element = labelled[k];
      var label = element.getAttribute('aria-label');
      var isControl = element.matches('button, a, [role="button"], [role="menuitem"]');
      if ((ROW_ACTIONS.indexOf(label) !== -1 && (isControl || element.querySelector('button'))) ||
          MISSING_PERMISSION.test(label)) {
        hide(element);
      }
    }
    var paths = root.querySelectorAll('svg path');
    for (var j = 0; j < paths.length; j++) {
      if (ICON_PATHS.indexOf(paths[j].getAttribute('d')) !== -1) {
        var owner = controlOf(paths[j]);
        if (owner) {
          hide(owner);
        }
      }
    }
  }

  function viewerMode() {
    var style = document.createElement('style');
    style.textContent = '[' + MARK + ']{display:none !important}' +
      '[' + TAB_MARK + ']{visibility:hidden !important;min-width:0 !important;max-width:0 !important;' +
      'padding:0 !important;margin:0 !important;border:0 !important;overflow:hidden !important}';
    document.head.appendChild(style);
    // Capture on window runs before Perses' key handlers, so they never see these keys.
    var lastD = 0;
    window.addEventListener('keydown', function (event) {
      var key = (event.key || '').toLowerCase();
      var target = event.target;
      var typing = target && (target.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(target.tagName));
      var plain = !event.ctrlKey && !event.metaKey && !event.altKey;
      var block = false;
      if ((event.ctrlKey || event.metaKey) && key === 's') {
        block = true;
      } else if (!typing && plain && key === 'm' && Date.now() - lastD < SEQUENCE_WINDOW_MS) {
        block = true;
      }
      if (!typing && plain && key === 'd') {
        lastD = Date.now();
      } else if (key !== 'shift') {
        lastD = 0;
      }
      if (block) {
        event.preventDefault();
        event.stopImmediatePropagation();
      }
    }, true);
    var observe = function () {
      scan(document);
      new MutationObserver(function () { scan(document); })
        .observe(document.body, { childList: true, subtree: true });
    };
    if (document.body) {
      observe();
    } else {
      document.addEventListener('DOMContentLoaded', observe);
    }
  }

  // Unknown or failed role checks hide controls (fail closed).
  var request = new XMLHttpRequest();
  request.open('GET', '/krate/role', false);  // synchronous: decide before Perses renders
  request.setRequestHeader('Cache-Control', 'no-store');
  try {
    request.send();
  } catch (error) {
    viewerMode();
    return;
  }
  if (request.status !== 200 || request.responseText.trim() !== 'admin') {
    viewerMode();
  }
})();
