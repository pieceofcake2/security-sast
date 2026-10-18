<?php
class ApiController extends AppController
{
    public $components = ['Security' => ['csrfCheck' => false, 'validatePost' => false]];
}
