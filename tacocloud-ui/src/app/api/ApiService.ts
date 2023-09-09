import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';

@Injectable()
export class ApiService {

  constructor(private httpClient: HttpClient) {
  }

  get(path: string) {
    return this.httpClient.get('http://localhost:8080' + path);
  }
}
