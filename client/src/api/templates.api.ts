import apiClient from './client';
import type { ApiResponse, DeviceBrand } from '@obliwan/shared';

/**
 * Templates and their revisions (M5).
 *
 * ┌─ WHAT THE SHAPE OF THIS API TELLS YOU ───────────────────────────────────┐
 * │ There is no `remove()`. Not an omission: the server has no `DELETE /:id`  │
 * │ either, because `config_renders.revision_id` is ON DELETE RESTRICT. A     │
 * │ template whose revisions produced renders that produced plans is          │
 * │ PROVENANCE — deleting it would orphan the answer to "why is this line on  │
 * │ this router". Archiving is a PATCH with `status: 'archived'`, which the   │
 * │ assignment resolver already honours.                                     │
 * │                                                                          │
 * │ And a revision is never edited. `publish()` freezes it; a change is a NEW │
 * │ revision. That is what makes a plan reproducible six months later.        │
 * └──────────────────────────────────────────────────────────────────────────┘
 */

export interface Template {
  id: string;
  uuid: string;
  name: string;
  description: string | null;
  brand: DeviceBrand | null;
  modelPattern: string | null;
  status: 'draft' | 'active' | 'archived' | string;
  /** True when this row is the shipped library: read-only for every tenant. */
  isLibrary: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface TemplateRevision {
  id: string;
  uuid: string;
  templateId: string;
  revision: number;
  bodySha256: string;
  varSchema: unknown;
  sectionSeverity: unknown;
  osMin: string | null;
  osMax: string | null;
  engine: string;
  renderOptions: unknown;
  status: 'draft' | 'published' | string;
  publishedAt: string | null;
}

export interface TemplateListParams {
  brand?: DeviceBrand;
  status?: string;
  includeLibrary?: boolean;
  limit?: number;
  offset?: number;
}

function clean(p: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(p)) if (v !== undefined && v !== null && v !== '') out[k] = v;
  return out;
}

export const templatesApi = {
  async list(params: TemplateListParams = {}): Promise<Template[]> {
    const res = await apiClient.get<ApiResponse<Template[]>>('/templates', {
      params: clean(params as Record<string, unknown>),
    });
    return res.data.data ?? [];
  },

  async get(id: string): Promise<Template> {
    const res = await apiClient.get<ApiResponse<Template>>(`/templates/${id}`);
    return res.data.data!;
  },

  async create(data: {
    name: string;
    description?: string | null;
    brand?: DeviceBrand | null;
    modelPattern?: string | null;
  }): Promise<Template> {
    const res = await apiClient.post<ApiResponse<Template>>('/templates', data);
    return res.data.data!;
  },

  async update(id: string, data: Partial<{
    name: string; description: string | null; brand: DeviceBrand | null;
    modelPattern: string | null; status: string;
  }>): Promise<Template> {
    const res = await apiClient.patch<ApiResponse<Template>>(`/templates/${id}`, data);
    return res.data.data!;
  },

  async revisions(id: string): Promise<TemplateRevision[]> {
    const res = await apiClient.get<ApiResponse<TemplateRevision[]>>(`/templates/${id}/revisions`);
    return res.data.data ?? [];
  },

  async createRevision(id: string, data: { body: string; note?: string | null }): Promise<TemplateRevision> {
    const res = await apiClient.post<ApiResponse<TemplateRevision>>(`/templates/${id}/revisions`, data);
    return res.data.data!;
  },

  /**
   * Freeze a revision. IRREVERSIBLE by design: a published revision is what a
   * plan pins itself to, and a mutable pin is not a pin.
   */
  async publish(revisionId: string): Promise<TemplateRevision> {
    const res = await apiClient.post<ApiResponse<TemplateRevision>>(
      `/templates/revisions/${revisionId}/publish`,
    );
    return res.data.data!;
  },

  async revision(revisionId: string): Promise<TemplateRevision & { body?: string }> {
    const res = await apiClient.get<ApiResponse<TemplateRevision & { body?: string }>>(
      `/templates/revisions/${revisionId}`,
    );
    return res.data.data!;
  },
};
