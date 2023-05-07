import { TestBed } from '@angular/core/testing';

import { FubukiNodeService } from './fubuki-node.service';

describe('FubukiNodeService', () => {
  let service: FubukiNodeService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(FubukiNodeService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
