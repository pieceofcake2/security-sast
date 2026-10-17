<?php
/**
 * A controller that prints a CSV: not a view, so the rule of the views does not apply
 */
class ExportController extends AppController
{
    public function csv()
    {
        $csv = 'id,title';
        echo $csv;
    }
}
