# Upstream Healer - Documentation Organization

## Overview
This document outlines the reorganized documentation structure for the Upstream Healer project. The goal is to remove redundant and obsolete content, consolidate information where appropriate, and create clear process documents for testing and CI/CD pipeline operations.

## Current Documentation Structure
The project now contains these documentation sources:
1. Main README.md - General project overview and usage
2. PIPELINE_PROCESS.md - Pipeline workflow details (consolidated)
3. TESTING_PROCESS.md - E2E testing framework (consolidated)
4. .gitlab-ci.yml - CI/CD pipeline definition
5. Memory bank files (context, architecture, progress, decisions, project-plan)
6. Docs directory with API documentation and test plans

## Redundant/Obsolete Content Identified

### 1. Redundant Pipeline Documentation
- PIPELINE_WORKFLOW.md (removed) - duplicated information from .gitlab-ci.yml and README.md
- END_TO_END_TESTING.md (removed) - overlapped with pipeline workflow descriptions

### 2. Duplicate Process Information
- Multiple files previously contained CI/CD workflow descriptions
- Similar information existed in both README and memory bank files

## Consolidated Documentation Plan

### Core Documentation Files

#### 1. README.md (Main Project Overview)
- Keep the current README but remove redundant sections
- Focus on: project purpose, features, requirements, quick start, usage instructions
- Remove database migration details which are better in dedicated docs

#### 2. PIPELINE_PROCESS.md (CI/CD Process)
- Create a new consolidated pipeline documentation file
- Include: pipeline stages, workflow sequence, dependencies, environment management
- Integrate information from .gitlab-ci.yml and PIPELINE_WORKFLOW.md

#### 3. TESTING_PROCESS.md (Testing Process)
- Create a comprehensive testing documentation file
- Cover: unit tests, E2E tests, test execution flow, test dependencies
- Include information from END_TO_END_TESTING.md and docs/E2E_TESTING_PLAN.md

#### 4. API_REFERENCE.md (API Documentation)
- Consolidate API documentation from the docs directory
- Create a clear reference for all endpoints with examples

### Memory Bank Organization

#### 1. CONTEXT.md (Project Context)
- Keep memory-bank/context.md but reorganize sections
- Focus on: repository info, what it is, purpose/motivation, tech stack, environment gotchas

#### 2. ARCHITECTURE.md (System Architecture)
- Keep memory-bank/architecture.md but reorganize for clarity
- Structure: Repository layout, Configuration, SQLite schema, Key flows

#### 3. DECISIONS.md (Design Decisions)
- Keep memory-bank/decisions.md as is - it contains valuable technical decisions
- This file should remain as a reference for implementation choices

### New Documentation Files to Create

1. **PIPELINE_PROCESS.md** - Detailed CI/CD pipeline process documentation
2. **TESTING_PROCESS.md** - Comprehensive testing framework documentation
3. **API_REFERENCE.md** - Complete API endpoint reference
4. **DEPLOYMENT_GUIDE.md** - Deployment procedures and environment management
5. **CONTRIBUTING.md** - Development workflow and contribution guidelines

This reorganization will provide:
- Clear separation of concerns between different types of documentation
- Elimination of redundant information
- Better process documentation for testing and pipeline operations
- Easier maintenance of documentation over time