#!/usr/bin/env node
import { installRuntimeGuards } from './runtime-guard.js';

installRuntimeGuards();
await import('./cli-app.js');
